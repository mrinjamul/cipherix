package crypt

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"filippo.io/edwards25519"
	"golang.org/x/crypto/ssh"
)

// ed25519SeedToX25519 derives an X25519 private key scalar from an Ed25519 seed.
// Following the age convention: SHA-512(seed), then clamp the first 32 bytes.
func ed25519SeedToX25519(seed []byte) []byte {
	h := sha512.Sum512(seed)
	scalar := h[:32]
	scalar[0] &= 248
	scalar[31] &= 127
	scalar[31] |= 64
	return scalar
}

// IsSSHPrivateKey reports whether data looks like an SSH private key.
func IsSSHPrivateKey(data []byte) bool {
	block, _ := pem.Decode(data)
	if block == nil {
		return false
	}
	switch block.Type {
	case "OPENSSH PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY", "DSA PRIVATE KEY":
		return true
	}
	return false
}

// IsSSHPublicKey reports whether a string looks like an SSH public key.
func IsSSHPublicKey(s string) bool {
	_, _, _, _, err := ssh.ParseAuthorizedKey([]byte(s))
	return err == nil
}

// ParseSSHIdentity parses an SSH private key and returns a PrivateKey.
// Supports ssh-ed25519 and ssh-rsa keys.
func ParseSSHIdentity(data []byte) (PrivateKey, error) {
	key, err := ssh.ParseRawPrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}

	switch k := key.(type) {
	case *ed25519.PrivateKey:
		seed := k.Seed()
		xScalar := ed25519SeedToX25519(seed)
		privateKey, err := ecdh.X25519().NewPrivateKey(xScalar)
		if err != nil {
			return nil, fmt.Errorf("ssh: invalid ed25519 key: %w", err)
		}
		return &x25519Identity{
			seed:   xScalar,
			public: privateKey.PublicKey().Bytes(),
		}, nil

	case *rsa.PrivateKey:
		if err := checkRSAPublicKey(&k.PublicKey); err != nil {
			return nil, fmt.Errorf("ssh: %w", err)
		}
		pubBytes, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("ssh: failed to marshal RSA public key: %w", err)
		}
		return &rsaIdentity{
			priv:   k,
			public: pubBytes,
		}, nil

	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", key)
	}
}

// ParseSSHRecipient parses an SSH public key string and returns a Recipient.
// Supports ssh-ed25519 and ssh-rsa keys.
func ParseSSHRecipient(recipient string) (Recipient, error) {
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(recipient))
	if err != nil {
		return nil, fmt.Errorf("ssh: %w", err)
	}

	switch k := pub.(type) {
	case ssh.CryptoPublicKey:
		cryptoPub := k.CryptoPublicKey()
		switch edPub := cryptoPub.(type) {
		case ed25519.PublicKey:
			xPub, err := ed25519PubToX25519(edPub)
			if err != nil {
				return nil, err
			}
			return newX25519Recipient(xPub)

		case *rsa.PublicKey:
			if err := checkRSAPublicKey(edPub); err != nil {
				return nil, fmt.Errorf("ssh: %w", err)
			}
			return &rsaRecipient{pub: edPub}, nil

		default:
			return nil, fmt.Errorf("ssh: unsupported public key type %T", cryptoPub)
		}

	default:
		return nil, fmt.Errorf("ssh: unsupported key type %T", pub)
	}
}

// ed25519PubToX25519 converts an Ed25519 public key (compressed Edwards form,
// 32 bytes) to an X25519 public key (Montgomery u-coordinate, 32 bytes).
func ed25519PubToX25519(edPub []byte) ([]byte, error) {
	point, err := new(edwards25519.Point).SetBytes(edPub)
	if err != nil {
		return nil, fmt.Errorf("invalid ed25519 public key: %w", err)
	}
	return point.BytesMontgomery(), nil
}
