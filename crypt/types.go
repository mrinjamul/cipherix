package crypt

import (
	"crypto/ecdh"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"fmt"
)

type KeyType int

const (
	KeyTypeX25519 KeyType = iota + 1
	KeyTypeRSA
)

func (kt KeyType) String() string {
	switch kt {
	case KeyTypeX25519:
		return "x25519"
	case KeyTypeRSA:
		return "rsa"
	default:
		return "unknown"
	}
}

type Recipient interface {
	KeyType() KeyType
	PublicBytes() []byte
	PublicString() string
}

type PrivateKey interface {
	KeyType() KeyType
	PublicBytes() []byte
	PrivateBytes() []byte
}

type x25519Recipient struct {
	pub *ecdh.PublicKey
}

func (r *x25519Recipient) KeyType() KeyType   { return KeyTypeX25519 }
func (r *x25519Recipient) PublicBytes() []byte { return r.pub.Bytes() }
func (r *x25519Recipient) PublicString() string {
	return PublicKeyToRecipient(r.pub.Bytes())
}

func newX25519Recipient(pub []byte) (*x25519Recipient, error) {
	k, err := ecdh.X25519().NewPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("invalid x25519 public key: %w", err)
	}
	return &x25519Recipient{pub: k}, nil
}

type rsaRecipient struct {
	pub *rsa.PublicKey
}

func (r *rsaRecipient) KeyType() KeyType { return KeyTypeRSA }
func (r *rsaRecipient) PublicBytes() []byte {
	return nil
}
func (r *rsaRecipient) PublicString() string {
	return fmt.Sprintf("ssh-rsa %x", sha256.Sum256(rsaPublicKeyBytes(r.pub)))
}

// EntryToRecipient converts a KeyStoreEntry to a Recipient.
func EntryToRecipient(e *KeyStoreEntry) (Recipient, error) {
	switch e.Type {
	case KeyTypeX25519:
		return NewX25519Recipient(e.Public)
	case KeyTypeRSA:
		pub, err := x509.ParsePKIXPublicKey(e.Public)
		if err != nil {
			return nil, fmt.Errorf("invalid RSA public key: %w", err)
		}
		rsaPub, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA public key")
		}
		return RecipientFromRSA(rsaPub), nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", e.Type)
	}
}

func rsaPublicKeyBytes(pub *rsa.PublicKey) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(pub.N.BitLen()))
	return append(buf, []byte(fmt.Sprintf("%x", pub.N))...)
}

type x25519Identity struct {
	seed   []byte
	public []byte
}

func (k *x25519Identity) KeyType() KeyType    { return KeyTypeX25519 }
func (k *x25519Identity) PublicBytes() []byte  { return k.public }
func (k *x25519Identity) PrivateBytes() []byte { return k.seed }

type rsaIdentity struct {
	priv   *rsa.PrivateKey
	public []byte
}

func (k *rsaIdentity) KeyType() KeyType    { return KeyTypeRSA }
func (k *rsaIdentity) PublicBytes() []byte  { return k.public }
func (k *rsaIdentity) PrivateBytes() []byte {
	b, _ := x509.MarshalPKCS8PrivateKey(k.priv)
	return b
}
