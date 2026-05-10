package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

func checkRSAPublicKey(pub *rsa.PublicKey) error {
	if pub.N.BitLen() < 2048 {
		return errors.New("RSA key too weak: minimum 2048 bits required")
	}
	return nil
}

func rsaSingleEncrypt(pub *rsa.PublicKey, data []byte, ext string) ([]byte, error) {
	if err := checkRSAPublicKey(pub); err != nil {
		return nil, err
	}

	contentKey := make([]byte, contentKeySize)
	if _, err := rand.Read(contentKey); err != nil {
		return nil, err
	}
	defer zeroBytes(contentKey)

	wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, contentKey, nil)
	if err != nil {
		return nil, fmt.Errorf("rsa oaep encrypt: %w", err)
	}

	h := &fileHeader{algo: algoPubKeyRSA, kdf: kdfRSAOAEP, ext: ext}
	header := h.marshal()

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	masterNonce := make([]byte, aesNonceSize)
	if _, err := rand.Read(masterNonce); err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	var buf bytes.Buffer
	buf.Write(header)

	wrapLen := make([]byte, 2)
	binary.BigEndian.PutUint16(wrapLen, uint16(len(wrappedKey)))
	buf.Write(wrapLen)
	buf.Write(wrappedKey)
	buf.Write(salt)
	buf.Write(masterNonce)

	var idx uint32
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		if err := writeChunk(&buf, gcm, masterNonce, idx, data[i:end]); err != nil {
			return nil, err
		}
		idx++
	}
	if err := writeTerminatorAndFooter(&buf, idx); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func rsaSingleDecrypt(priv *rsa.PrivateKey, data []byte) ([]byte, string, error) {
	hdr, hdrLen, err := parseHeader(data)
	if err != nil {
		return nil, "", err
	}
	if hdr.algo != algoPubKeyRSA {
		return nil, "", ErrUnsupportedAlgo
	}
	payload := data[hdrLen:]

	if len(payload) < 2+saltLen+aesNonceSize {
		return nil, "", ErrCorruptedData
	}
	off := 0
	wrapLen := int(binary.BigEndian.Uint16(payload[off:]))
	off += 2
	if off+wrapLen > len(payload) {
		return nil, "", ErrCorruptedData
	}
	wrappedKey := payload[off : off+wrapLen]
	off += wrapLen

	off += saltLen
	masterNonce := payload[off : off+aesNonceSize]
	off += aesNonceSize
	chunkData := payload[off:]

	contentKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, wrappedKey, nil)
	if err != nil {
		return nil, "", ErrWrongPassword
	}
	defer zeroBytes(contentKey)

	blockCipher, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, "", err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, "", err
	}

	var plaintext bytes.Buffer
	r := bytes.NewReader(chunkData)
	var idx uint32
	for {
		pt, err := readChunk(r, gcm, masterNonce, idx)
		if err != nil {
			return nil, "", ErrWrongPassword
		}
		if pt == nil {
			break
		}
		plaintext.Write(pt)
		idx++
	}
	if err := readTerminatorAndFooter(r, idx); err != nil {
		return nil, "", err
	}
	return plaintext.Bytes(), hdr.ext, nil
}

func rsaMultiEncrypt(pubs []*rsa.PublicKey, data []byte, ext string) ([]byte, error) {
	if len(pubs) == 0 {
		return nil, errors.New("at least one recipient required")
	}
	for _, pub := range pubs {
		if err := checkRSAPublicKey(pub); err != nil {
			return nil, fmt.Errorf("recipient: %w", err)
		}
	}
	if len(pubs) == 1 {
		return rsaSingleEncrypt(pubs[0], data, ext)
	}

	contentKey := make([]byte, contentKeySize)
	if _, err := rand.Read(contentKey); err != nil {
		return nil, err
	}
	defer zeroBytes(contentKey)

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	dataNonce := make([]byte, aesNonceSize)
	if _, err := rand.Read(dataNonce); err != nil {
		return nil, err
	}

	var entriesBuf bytes.Buffer
	entriesBuf.WriteByte(byte(len(pubs)))
	for _, pub := range pubs {
		wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, contentKey, nil)
		if err != nil {
			return nil, fmt.Errorf("rsa oaep encrypt: %w", err)
		}
		lenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(lenBuf, uint16(len(wrappedKey)))
		entriesBuf.Write(lenBuf)
		entriesBuf.Write(wrappedKey)
	}

	blockCipher, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	h := &fileHeader{algo: algoPubKeyRSAMulti, kdf: kdfRSAOAEP, ext: ext}
	header := h.marshal()

	var buf bytes.Buffer
	buf.Write(header)
	buf.Write(salt)
	buf.Write(dataNonce)
	buf.Write(entriesBuf.Bytes())

	var idx uint32
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		if err := writeChunk(&buf, gcm, dataNonce, idx, data[i:end]); err != nil {
			return nil, err
		}
		idx++
	}
	if err := writeTerminatorAndFooter(&buf, idx); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func rsaMultiDecrypt(priv *rsa.PrivateKey, data []byte) ([]byte, string, error) {
	hdr, hdrLen, err := parseHeader(data)
	if err != nil {
		return nil, "", err
	}
	if hdr.algo != algoPubKeyRSAMulti {
		return nil, "", ErrUnsupportedAlgo
	}
	payload := data[hdrLen:]

	if len(payload) < saltLen+aesNonceSize+1 {
		return nil, "", ErrCorruptedData
	}
	off := 0
	off += saltLen
	dataNonce := payload[off : off+aesNonceSize]
	off += aesNonceSize
	numRecipients := int(payload[off])
	off += 1

	// Compute entriesEnd separately so we can skip remaining entries
	// after finding a match without corrupting the chunk data offset.
	entriesStart := off
	entriesEnd := entriesStart
	for i := 0; i < numRecipients; i++ {
		if entriesEnd+2 > len(payload) {
			return nil, "", ErrCorruptedData
		}
		wrapLen := int(binary.BigEndian.Uint16(payload[entriesEnd:]))
		entriesEnd += 2 + wrapLen
	}
	if entriesEnd > len(payload) {
		return nil, "", ErrCorruptedData
	}

	var contentKey []byte
	parseOff := entriesStart
	for i := 0; i < numRecipients; i++ {
		wrapLen := int(binary.BigEndian.Uint16(payload[parseOff:]))
		parseOff += 2
		wrapped := payload[parseOff : parseOff+wrapLen]
		parseOff += wrapLen

		ck, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, wrapped, nil)
		if err == nil {
			contentKey = ck
			break
		}
	}
	if contentKey == nil {
		return nil, "", ErrWrongPassword
	}
	defer zeroBytes(contentKey)

	chunkData := payload[entriesEnd:]

	blockCipher, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, "", err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, "", err
	}

	var plaintext bytes.Buffer
	r := bytes.NewReader(chunkData)
	var idx uint32
	for {
		pt, err := readChunk(r, gcm, dataNonce, idx)
		if err != nil {
			return nil, "", ErrWrongPassword
		}
		if pt == nil {
			break
		}
		plaintext.Write(pt)
		idx++
	}
	if err := readTerminatorAndFooter(r, idx); err != nil {
		return nil, "", err
	}
	return plaintext.Bytes(), hdr.ext, nil
}

func hybridEncrypt(recips []Recipient, data []byte, ext string) ([]byte, error) {
	if len(recips) == 0 {
		return nil, errors.New("at least one recipient required")
	}

	contentKey := make([]byte, contentKeySize)
	if _, err := rand.Read(contentKey); err != nil {
		return nil, err
	}
	defer zeroBytes(contentKey)

	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ephemeralPub := ephemeral.PublicKey().Bytes()

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	dataNonce := make([]byte, aesNonceSize)
	if _, err := rand.Read(dataNonce); err != nil {
		return nil, err
	}

	var entriesBuf bytes.Buffer
	entriesBuf.WriteByte(byte(len(recips)))

	for _, r := range recips {
		switch r.KeyType() {
		case KeyTypeX25519:
			entriesBuf.WriteByte(0)
			xr := r.(*x25519Recipient)
			sharedSecret, err := ephemeral.ECDH(xr.pub)
			if err != nil {
				return nil, err
			}
			h := hkdf.New(sha256.New, sharedSecret, salt, []byte("cipherix-multi"))
			wrapKey := make([]byte, 32)
			if _, err := io.ReadFull(h, wrapKey); err != nil {
				return nil, err
			}
			blockCipher, err := aes.NewCipher(wrapKey)
			if err != nil {
				return nil, err
			}
			gcm, err := cipher.NewGCM(blockCipher)
			if err != nil {
				return nil, err
			}
			wrapNonce := make([]byte, wrapNonceSize)
			if _, err := rand.Read(wrapNonce); err != nil {
				return nil, err
			}
			wrapped := gcm.Seal(nil, wrapNonce, contentKey, nil)
			entriesBuf.Write(wrapNonce)
			entriesBuf.Write(wrapped)
			zeroBytes(sharedSecret)
			zeroBytes(wrapKey)

		case KeyTypeRSA:
			entriesBuf.WriteByte(1)
			rr := r.(*rsaRecipient)
			wrappedKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, rr.pub, contentKey, nil)
			if err != nil {
				return nil, fmt.Errorf("rsa oaep encrypt: %w", err)
			}
			lenBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(lenBuf, uint16(len(wrappedKey)))
			entriesBuf.Write(lenBuf)
			entriesBuf.Write(wrappedKey)
		}
	}

	blockCipher, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	h := &fileHeader{algo: algoPubKeyHybrid, kdf: kdfRSAOAEP, ext: ext}
	header := h.marshal()

	var buf bytes.Buffer
	buf.Write(header)
	buf.Write(ephemeralPub)
	buf.Write(salt)
	buf.Write(dataNonce)
	buf.Write(entriesBuf.Bytes())

	var idx uint32
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		if err := writeChunk(&buf, gcm, dataNonce, idx, data[i:end]); err != nil {
			return nil, err
		}
		idx++
	}
	if err := writeTerminatorAndFooter(&buf, idx); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func hybridDecrypt(priv PrivateKey, data []byte) ([]byte, string, error) {
	hdr, hdrLen, err := parseHeader(data)
	if err != nil {
		return nil, "", err
	}
	if hdr.algo != algoPubKeyHybrid {
		return nil, "", ErrUnsupportedAlgo
	}
	payload := data[hdrLen:]

	if len(payload) < pubKeyLen+saltLen+aesNonceSize+1 {
		return nil, "", ErrCorruptedData
	}
	off := 0
	ephemeralPub := payload[off : off+pubKeyLen]
	off += pubKeyLen
	salt := payload[off : off+saltLen]
	off += saltLen
	dataNonce := payload[off : off+aesNonceSize]
	off += aesNonceSize
	numRecipients := int(payload[off])
	off += 1

	// Compute entriesEnd separately to avoid corrupting chunk offset on early break.
	entriesStart := off
	entriesEnd := entriesStart
	for i := 0; i < numRecipients; i++ {
		if entriesEnd >= len(payload) {
			return nil, "", ErrCorruptedData
		}
		entryType := payload[entriesEnd]
		entriesEnd++
		if entryType == 0 {
			entriesEnd += wrapNonceSize + wrappedContentSize
		} else {
			if entriesEnd+2 > len(payload) {
				return nil, "", ErrCorruptedData
			}
			wrapLen := int(binary.BigEndian.Uint16(payload[entriesEnd:]))
			entriesEnd += 2 + wrapLen
		}
	}
	if entriesEnd > len(payload) {
		return nil, "", ErrCorruptedData
	}

	var contentKey []byte
	parseOff := entriesStart
	for i := 0; i < numRecipients; i++ {
		entryType := payload[parseOff]
		parseOff++

		if entryType == 0 && priv.KeyType() == KeyTypeX25519 {
			wrapNonce := payload[parseOff : parseOff+wrapNonceSize]
			parseOff += wrapNonceSize
			wrapped := payload[parseOff : parseOff+wrappedContentSize]
			parseOff += wrappedContentSize

			var seed []byte
			switch k := priv.(type) {
			case *Identity:
				seed = k.Seed
			case *x25519Identity:
				seed = k.seed
			default:
				continue
			}

			privateKey, err := ecdh.X25519().NewPrivateKey(seed)
			if err != nil {
				continue
			}
			ephKey, err := ecdh.X25519().NewPublicKey(ephemeralPub)
			if err != nil {
				continue
			}
			sharedSecret, err := privateKey.ECDH(ephKey)
			if err != nil {
				continue
			}
			h := hkdf.New(sha256.New, sharedSecret, salt, []byte("cipherix-multi"))
			wrapKey := make([]byte, 32)
			if _, err := io.ReadFull(h, wrapKey); err != nil {
				continue
			}
			blockCipher, err := aes.NewCipher(wrapKey)
			if err != nil {
				continue
			}
			gcm, err := cipher.NewGCM(blockCipher)
			if err != nil {
				continue
			}
			ck, err := gcm.Open(nil, wrapNonce, wrapped, nil)
			if err == nil {
				contentKey = ck
				zeroBytes(sharedSecret)
				zeroBytes(wrapKey)
				break
			}
		} else if entryType == 1 && priv.KeyType() == KeyTypeRSA {
			wrapLen := int(binary.BigEndian.Uint16(payload[parseOff:]))
			parseOff += 2
			wrapped := payload[parseOff : parseOff+wrapLen]
			parseOff += wrapLen

			var rsaPriv *rsa.PrivateKey
			switch k := priv.(type) {
			case *rsaIdentity:
				rsaPriv = k.priv
			default:
				continue
			}

			ck, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, rsaPriv, wrapped, nil)
			if err == nil {
				contentKey = ck
				break
			}
		} else {
			if entryType == 0 {
				parseOff += wrapNonceSize + wrappedContentSize
			} else {
				wrapLen := int(binary.BigEndian.Uint16(payload[parseOff:]))
				parseOff += 2 + wrapLen
			}
		}
	}
	if contentKey == nil {
		return nil, "", ErrWrongPassword
	}
	defer zeroBytes(contentKey)

	chunkData := payload[entriesEnd:]
	blockCipher, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, "", err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, "", err
	}

	var plaintext bytes.Buffer
	r := bytes.NewReader(chunkData)
	var idx uint32
	for {
		pt, err := readChunk(r, gcm, dataNonce, idx)
		if err != nil {
			return nil, "", ErrWrongPassword
		}
		if pt == nil {
			break
		}
		plaintext.Write(pt)
		idx++
	}
	if err := readTerminatorAndFooter(r, idx); err != nil {
		return nil, "", err
	}
	return plaintext.Bytes(), hdr.ext, nil
}




