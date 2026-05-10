package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/scrypt"
)

// File format constants.
const (
	magic         = "goenc"
	magicLen      = 5
	headerVersion = 1

	headerBaseLen = magicLen + 4 // magic + version + algo + kdf + extLen

	algoAES          = 0
	algoChaCha       = 1
	algoPubKey       = 2 // X25519 + ephemeral key exchange (single recipient)
	algoPubKeyMulti  = 3 // X25519 + wrapped content key (multiple recipients)
	algoPubKeyRSA    = 4 // RSA-OAEP wrapped content key (single recipient)
	algoPubKeyRSAMulti = 5 // RSA-OAEP wrapped content key (multiple recipients)
	algoPubKeyHybrid = 6 // Mixed RSA + X25519 recipients

	kdfScrypt   = 0
	kdfArgon2id = 1
	kdfECDH     = 2
	kdfRSAOAEP  = 3

	saltLen       = 32
	extTrailerLen = 3 // old v1 format trailer length

	chunkSize          = 64 * 1024 // 64 KiB plaintext per chunk
	chunkLenSize       = 4         // uint32 for chunk length
	chunkTerm          = 0         // chunk length value marking end-of-stream
	aesNonceSize       = 12
	contentKeySize     = 32        // AES-256 content key
	wrapNonceSize      = 12
	wrappedContentSize = 48 // content key (32) + GCM tag (16)
	entryHeadSize      = 1  // num_recipients byte
)

// Errors.
var (
	ErrUnknownFormat   = errors.New("unknown encrypted file format")
	ErrWrongPassword   = errors.New("wrong password")
	ErrUnsupportedAlgo = errors.New("unsupported algorithm")
	ErrCorruptedData   = errors.New("corrupted encrypted data")
)

func zeroBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

// MethodsAvailable is a list of supported encryption methods.
var MethodsAvailable = []string{"aes", "aes256", "chacha20", "chacha20poly1305"}

// ChaCha20 KDF parameters.
var (
	NonceSize  = 24
	KeySize    = uint32(32)
	KeyTime    = uint32(5)
	KeyMemory  = uint32(1024 * 64) // 64 MiB
	KeyThreads = uint8(4)
)

// fileHeader is the v2 binary header.
type fileHeader struct {
	algo byte
	kdf  byte
	ext  string
}

func (h *fileHeader) marshal() []byte {
	extBytes := []byte(h.ext)
	if len(extBytes) > 255 {
		extBytes = extBytes[:255]
	}
	buf := make([]byte, headerBaseLen+len(extBytes))
	copy(buf[0:magicLen], magic)
	buf[magicLen+0] = headerVersion
	buf[magicLen+1] = h.algo
	buf[magicLen+2] = h.kdf
	buf[magicLen+3] = byte(len(extBytes))
	copy(buf[headerBaseLen:], extBytes)
	return buf
}

func parseHeader(data []byte) (*fileHeader, int, error) {
	if len(data) < headerBaseLen || string(data[:magicLen]) != magic {
		return nil, 0, ErrUnknownFormat
	}
	if data[magicLen] != headerVersion {
		return nil, 0, fmt.Errorf("unsupported header version: %d", data[magicLen])
	}
	extLen := int(data[magicLen+3])
	if headerBaseLen+extLen > len(data) {
		return nil, 0, ErrCorruptedData
	}
	h := &fileHeader{
		algo: data[magicLen+1],
		kdf:  data[magicLen+2],
		ext:  string(data[headerBaseLen : headerBaseLen+extLen]),
	}
	return h, headerBaseLen + extLen, nil
}

func (h *fileHeader) algoString() string {
	switch h.algo {
	case algoAES:
		return "aes"
	case algoChaCha:
		return "chacha20"
	case algoPubKey:
		return "pubkey"
	case algoPubKeyMulti:
		return "pubkey-multi"
	case algoPubKeyRSA:
		return "pubkey-rsa"
	case algoPubKeyRSAMulti:
		return "pubkey-rsa-multi"
	case algoPubKeyHybrid:
		return "pubkey-hybrid"
	default:
		return "unknown"
	}
}

// KDF helpers.

func deriveKeyAES(password, salt []byte) ([]byte, error) {
	if salt == nil {
		salt = make([]byte, saltLen)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
	}
	return scrypt.Key(password, salt, 1<<16, 8, 1, 32)
}

func deriveKeyChaCha(password, salt []byte) []byte {
	return argon2.IDKey(password, salt, KeyTime, KeyMemory, KeyThreads, KeySize)
}

// deriveNonce derives a per-chunk nonce from the master nonce and chunk index.
func deriveNonce(master []byte, idx uint32) []byte {
	nonce := make([]byte, len(master))
	copy(nonce, master)
	last := binary.BigEndian.Uint32(nonce[len(nonce)-4:])
	binary.BigEndian.PutUint32(nonce[len(nonce)-4:], last^idx)
	return nonce
}

// writeChunk encrypts a chunk of plaintext and writes it to out.
func writeChunk(out io.Writer, gcm cipher.AEAD, masterNonce []byte, idx uint32, plaintext []byte) error {
	nonce := deriveNonce(masterNonce, idx)
	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)

	lenBuf := make([]byte, chunkLenSize)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(ciphertext)))
	if _, err := out.Write(lenBuf); err != nil {
		return err
	}
	_, err := out.Write(ciphertext)
	return err
}

// readChunk reads and decrypts a chunk from in.
func readChunk(in io.Reader, gcm cipher.AEAD, masterNonce []byte, idx uint32) ([]byte, error) {
	var lenBuf [chunkLenSize]byte
	if _, err := io.ReadFull(in, lenBuf[:]); err != nil {
		return nil, err
	}
	chunkLen := binary.BigEndian.Uint32(lenBuf[:])
	if chunkLen == chunkTerm {
		return nil, nil // end of stream
	}

	ciphertext := make([]byte, chunkLen)
	if _, err := io.ReadFull(in, ciphertext); err != nil {
		return nil, err
	}

	nonce := deriveNonce(masterNonce, idx)
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// writeTerminator writes the chunk terminator and total chunk count footer.
// The footer enables truncation detection on decrypt.
func writeTerminatorAndFooter(w io.Writer, numChunks uint32) error {
	var term [chunkLenSize]byte
	binary.BigEndian.PutUint32(term[:], chunkTerm)
	if _, err := w.Write(term[:]); err != nil {
		return err
	}
	var footer [4]byte
	binary.BigEndian.PutUint32(footer[:], numChunks)
	_, err := w.Write(footer[:])
	return err
}

// readTerminatorAndFooter reads past the chunk terminator and optional
// chunk count footer. Returns an error if the footer is present but doesn't
// match the number of chunks actually read.
func readTerminatorAndFooter(r io.Reader, numChunks uint32) error {
	// Read terminator (4 zero bytes).
	var term [chunkLenSize]byte
	if _, err := io.ReadFull(r, term[:]); err != nil {
		return err
	}
	// Try to read the optional 4-byte footer.
	var footer [4]byte
	if _, err := io.ReadFull(r, footer[:]); err != nil {
		return nil // old format without footer, skip check
	}
	expected := binary.BigEndian.Uint32(footer[:])
	if numChunks != expected {
		return ErrCorruptedData
	}
	return nil
}

// v2 format encrypt/decrypt (chunked AEAD).

func aesEncryptV2(password []byte, data []byte, ext string) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	dk, err := deriveKeyAES(password, salt)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(dk)

	blockCipher, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	masterNonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(masterNonce); err != nil {
		return nil, err
	}

	h := &fileHeader{algo: algoAES, kdf: kdfScrypt, ext: ext}
	header := h.marshal()

	var buf bytes.Buffer
	buf.Write(header)
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

func aesDecryptV2(password []byte, payload []byte) ([]byte, error) {
	if len(payload) < saltLen+aesNonceSize {
		return nil, ErrCorruptedData
	}
	salt := payload[:saltLen]
	masterNonce := payload[saltLen : saltLen+aesNonceSize]
	chunkData := payload[saltLen+aesNonceSize:]

	dk, err := deriveKeyAES(password, salt)
	if err != nil {
		return nil, err
	}

	blockCipher, err := aes.NewCipher(dk)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	var plaintext bytes.Buffer
	r := bytes.NewReader(chunkData)
	var idx uint32
	for {
		pt, err := readChunk(r, gcm, masterNonce, idx)
		if err != nil {
			return nil, err
		}
		if pt == nil {
			break // end of stream
		}
		plaintext.Write(pt)
		idx++
	}
	if err := readTerminatorAndFooter(r, idx); err != nil {
		return nil, err
	}
	return plaintext.Bytes(), nil
}

func chachaEncryptV2(password []byte, data []byte, ext string) ([]byte, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	dk := deriveKeyChaCha(password, salt)
	defer zeroBytes(dk)
	aead, err := chacha20poly1305.NewX(dk)
	if err != nil {
		return nil, err
	}

	masterNonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(masterNonce); err != nil {
		return nil, err
	}

	h := &fileHeader{algo: algoChaCha, kdf: kdfArgon2id, ext: ext}
	header := h.marshal()

	var buf bytes.Buffer
	buf.Write(header)
	buf.Write(salt)
	buf.Write(masterNonce)

	var idx uint32
	for i := 0; i < len(data); i += chunkSize {
		end := i + chunkSize
		if end > len(data) {
			end = len(data)
		}
		if err := writeChunk(&buf, aead, masterNonce, idx, data[i:end]); err != nil {
			return nil, err
		}
		idx++
	}
	if err := writeTerminatorAndFooter(&buf, idx); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

func chachaDecryptV2(password []byte, payload []byte) ([]byte, error) {
	if len(payload) < saltLen+NonceSize {
		return nil, ErrCorruptedData
	}
	salt := payload[:saltLen]
	masterNonce := payload[saltLen : saltLen+NonceSize]
	chunkData := payload[saltLen+NonceSize:]

	dk := deriveKeyChaCha(password, salt)
	aead, err := chacha20poly1305.NewX(dk)
	if err != nil {
		return nil, err
	}

	var plaintext bytes.Buffer
	r := bytes.NewReader(chunkData)
	var idx uint32
	for {
		pt, err := readChunk(r, aead, masterNonce, idx)
		if err != nil {
			return nil, err
		}
		if pt == nil {
			break
		}
		plaintext.Write(pt)
		idx++
	}
	if err := readTerminatorAndFooter(r, idx); err != nil {
		return nil, err
	}
	return plaintext.Bytes(), nil
}

// Streaming API.

// StreamEncrypt encrypts data from reader to writer.
// Returns the number of bytes written on success.
func StreamEncrypt(password []byte, in io.Reader, out io.Writer, algorithm, ext string) (int64, error) {
	switch algorithm {
	case "aes":
		return streamEncryptAES(password, in, out, ext)
	case "chacha20", "xchacha20":
		return streamEncryptChaCha(password, in, out, ext)
	default:
		return 0, ErrUnsupportedAlgo
	}
}

func streamEncryptAES(password []byte, in io.Reader, out io.Writer, ext string) (int64, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return 0, err
	}
	dk, err := deriveKeyAES(password, salt)
	if err != nil {
		return 0, err
	}

	blockCipher, err := aes.NewCipher(dk)
	if err != nil {
		return 0, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return 0, err
	}

	masterNonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(masterNonce); err != nil {
		return 0, err
	}

	h := &fileHeader{algo: algoAES, kdf: kdfScrypt, ext: ext}
	header := h.marshal()
	if _, err := out.Write(header); err != nil {
		return 0, err
	}
	if _, err := out.Write(salt); err != nil {
		return 0, err
	}
	if _, err := out.Write(masterNonce); err != nil {
		return 0, err
	}

	var written int64
	buf := make([]byte, chunkSize)
	var idx uint32
	for {
		n, err := io.ReadFull(in, buf)
		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return written, err
		}
		if err := writeChunk(out, gcm, masterNonce, idx, buf[:n]); err != nil {
			return written, err
		}
		written += int64(n)
		idx++
	}
	if err := writeTerminatorAndFooter(out, idx); err != nil {
		return written, err
	}
	return written, nil
}

func streamEncryptChaCha(password []byte, in io.Reader, out io.Writer, ext string) (int64, error) {
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return 0, err
	}

	dk := deriveKeyChaCha(password, salt)
	aead, err := chacha20poly1305.NewX(dk)
	if err != nil {
		return 0, err
	}

	masterNonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(masterNonce); err != nil {
		return 0, err
	}

	h := &fileHeader{algo: algoChaCha, kdf: kdfArgon2id, ext: ext}
	header := h.marshal()
	if _, err := out.Write(header); err != nil {
		return 0, err
	}
	if _, err := out.Write(salt); err != nil {
		return 0, err
	}
	if _, err := out.Write(masterNonce); err != nil {
		return 0, err
	}

	var written int64
	buf := make([]byte, chunkSize)
	var idx uint32
	for {
		n, err := io.ReadFull(in, buf)
		if err == io.EOF {
			break
		}
		if err != nil && err != io.ErrUnexpectedEOF {
			return written, err
		}
		if err := writeChunk(out, aead, masterNonce, idx, buf[:n]); err != nil {
			return written, err
		}
		written += int64(n)
		idx++
	}
	if err := writeTerminatorAndFooter(out, idx); err != nil {
		return written, err
	}
	return written, nil
}

// StreamDecrypt decrypts data from reader to writer, auto-detecting format.
// Returns the original extension on success.
func StreamDecrypt(password []byte, in io.Reader, out io.Writer) (string, error) {
	// Read header magic to detect format.
	var magicBuf [magicLen]byte
	if _, err := io.ReadFull(in, magicBuf[:]); err != nil {
		return "", ErrUnknownFormat
	}

	if string(magicBuf[:]) != magic {
		// v1 format not supported via streaming (requires full data in memory).
		return "", ErrUnknownFormat
	}

	return streamDecryptV2(password, in, out)
}

func streamDecryptV2(password []byte, in io.Reader, out io.Writer) (string, error) {
	// Read the rest of the header (version + algo + kdf + extLen).
	var hdrTail [4]byte
	if _, err := io.ReadFull(in, hdrTail[:]); err != nil {
		return "", ErrCorruptedData
	}

	ver := hdrTail[0]
	algo := hdrTail[1]
	kdf := hdrTail[2]
	extLen := int(hdrTail[3])

	if ver != headerVersion {
		return "", fmt.Errorf("unsupported header version: %d", ver)
	}

	extBytes := make([]byte, extLen)
	if _, err := io.ReadFull(in, extBytes); err != nil {
		return "", ErrCorruptedData
	}
	ext := string(extBytes)

	// Read salt.
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(in, salt); err != nil {
		return "", ErrCorruptedData
	}

	switch algo {
	case algoAES:
		if err := streamDecryptAES(password, in, out, salt, kdf); err != nil {
			return "", err
		}
	case algoChaCha:
		if err := streamDecryptChaCha(password, in, out, salt, kdf); err != nil {
			return "", err
		}
	default:
		return "", ErrUnsupportedAlgo
	}

	return ext, nil
}

func streamDecryptAES(password []byte, in io.Reader, out io.Writer, salt []byte, kdfType byte) error {
	dk, err := deriveKeyAES(password, salt)
	if err != nil {
		return err
	}

	blockCipher, err := aes.NewCipher(dk)
	if err != nil {
		return err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return err
	}

	masterNonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(in, masterNonce); err != nil {
		return ErrCorruptedData
	}

	var idx uint32
	for {
		pt, err := readChunk(in, gcm, masterNonce, idx)
		if err != nil {
			return ErrWrongPassword
		}
		if pt == nil {
			break
		}
		if _, err := out.Write(pt); err != nil {
			return err
		}
		idx++
	}
	return readTerminatorAndFooter(in, idx)
}

func streamDecryptChaCha(password []byte, in io.Reader, out io.Writer, salt []byte, kdfType byte) error {
	dk := deriveKeyChaCha(password, salt)
	aead, err := chacha20poly1305.NewX(dk)
	if err != nil {
		return err
	}

	masterNonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(in, masterNonce); err != nil {
		return ErrCorruptedData
	}

	var idx uint32
	for {
		pt, err := readChunk(in, aead, masterNonce, idx)
		if err != nil {
			return ErrWrongPassword
		}
		if pt == nil {
			break
		}
		if _, err := out.Write(pt); err != nil {
			return err
		}
		idx++
	}
	return readTerminatorAndFooter(in, idx)
}

// v1 (old format) compat helpers.

// aesDecryptV1 handles the old AES format:
//
//	[nonce(12)][ciphertext+tag][salt(32)]
//	plaintext carries 3-byte extension trailer.
func aesDecryptV1(key, data []byte) ([]byte, string, error) {
	if len(data) < saltLen+12+16 {
		return nil, "", ErrCorruptedData
	}
	salt := data[len(data)-saltLen:]
	ciphertext := data[:len(data)-saltLen]

	dk, err := deriveKeyAES(key, salt)
	if err != nil {
		return nil, "", err
	}

	blockCipher, err := aes.NewCipher(dk)
	if err != nil {
		return nil, "", err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, "", err
	}

	nonce := ciphertext[:12]
	ct := ciphertext[12:]

	plaintext, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, "", err
	}

	ext := string(plaintext[len(plaintext)-extTrailerLen:])
	plaintext = plaintext[:len(plaintext)-extTrailerLen]
	return plaintext, ext, nil
}

// chachaDecryptV1 handles the old ChaCha20 format:
//
//	[ciphertext+tag][salt(32)][nonce(24)]
//	plaintext carries 3-byte extension trailer.
func chachaDecryptV1(key, data []byte) ([]byte, string, error) {
	if len(data) < saltLen+NonceSize+16 {
		return nil, "", ErrCorruptedData
	}
	nonce := data[len(data)-NonceSize:]
	salt := data[len(data)-saltLen-NonceSize : len(data)-NonceSize]
	ciphertext := data[:len(data)-saltLen-NonceSize]

	dk := deriveKeyChaCha(key, salt)

	aead, err := chacha20poly1305.NewX(dk)
	if err != nil {
		return nil, "", err
	}

	plaintext, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, "", err
	}

	ext := string(plaintext[len(plaintext)-extTrailerLen:])
	plaintext = plaintext[:len(plaintext)-extTrailerLen]
	return plaintext, ext, nil
}

// isV2Format reports whether data starts with the goenc magic.
func isV2Format(data []byte) bool {
	return len(data) >= magicLen && string(data[:magicLen]) == magic
}

// Public API.

// Encrypt encrypts data using the given algorithm and password.
// Returns v2-format ciphertext with embedded extension.
//
// Supported algorithms: "aes", "chacha20".
func Encrypt(password, data []byte, algorithm, ext string) ([]byte, error) {
	switch algorithm {
	case "aes":
		return aesEncryptV2(password, data, ext)
	case "chacha20", "xchacha20":
		return chachaEncryptV2(password, data, ext)
	default:
		return nil, ErrUnsupportedAlgo
	}
}

// Decrypt decrypts data, auto-detecting v2 (header) vs v1 (old trailer) format
// and the encryption algorithm.
//
// Returns (plaintext, original extension, error).
func Decrypt(password, data []byte) ([]byte, string, error) {
	if isV2Format(data) {
		return decryptV2(password, data)
	}
	return decryptV1(password, data)
}

func decryptV2(password, data []byte) ([]byte, string, error) {
	hdr, hdrLen, err := parseHeader(data)
	if err != nil {
		return nil, "", err
	}
	payload := data[hdrLen:]

	if len(payload) < saltLen {
		return nil, "", ErrCorruptedData
	}

	var plaintext []byte
	switch hdr.algo {
	case algoAES:
		plaintext, err = aesDecryptV2(password, payload)
	case algoChaCha:
		plaintext, err = chachaDecryptV2(password, payload)
	default:
		return nil, "", ErrUnsupportedAlgo
	}
	if err != nil {
		return nil, "", ErrWrongPassword
	}
	return plaintext, hdr.ext, nil
}

func decryptV1(password, data []byte) ([]byte, string, error) {
	// Try AES first (more common).
	plaintext, ext, err := aesDecryptV1(password, data)
	if err == nil {
		return plaintext, ext, nil
	}

	// Fall back to ChaCha20.
	plaintext, ext, err = chachaDecryptV1(password, data)
	if err != nil {
		return nil, "", ErrWrongPassword
	}
	return plaintext, ext, nil
}

// Inspect returns the algorithm and extension from encrypted data without
// decrypting. Works with both v2 (header) and v1 (best-effort) formats.
func Inspect(data []byte) (algorithm string, extension string, err error) {
	if isV2Format(data) {
		hdr, _, err := parseHeader(data)
		if err != nil {
			return "", "", err
		}
		return hdr.algoString(), hdr.ext, nil
	}
	return "", "", ErrUnknownFormat
}

// FileInfo holds metadata about an encrypted file (from header only, no decrypt).
type FileInfo struct {
	FormatVersion int
	Algorithm     string
	KDF           string
	Extension     string
	NumRecipients int
	RecipientIDs  []string
}

// InspectFileInfo returns detailed metadata from encrypted data without decrypting.
func InspectFileInfo(data []byte) (*FileInfo, error) {
	if !isV2Format(data) {
		return nil, ErrUnknownFormat
	}
	hdr, hdrLen, err := parseHeader(data)
	if err != nil {
		return nil, err
	}
	payload := data[hdrLen:]

	fi := &FileInfo{
		FormatVersion: int(headerVersion),
		Algorithm:     hdr.algoString(),
		KDF:           kdfString(hdr.kdf),
		Extension:     hdr.ext,
	}

	switch hdr.algo {
	case algoPubKey:
		fi.NumRecipients = 1
	case algoPubKeyMulti:
		off := 0
		off += pubKeyLen
		off += saltLen
		off += aesNonceSize
		if off+entryHeadSize > len(payload) {
			return nil, ErrCorruptedData
		}
		numRecipients := int(payload[off])
		fi.NumRecipients = numRecipients
		off += entryHeadSize

		entrySize := wrapNonceSize + wrappedContentSize
		if off+numRecipients*entrySize > len(payload) {
			return nil, ErrCorruptedData
		}
		for i := 0; i < numRecipients; i++ {
			entryOff := off + i*entrySize
			wrapNonce := payload[entryOff : entryOff+wrapNonceSize]
			wrapped := payload[entryOff+wrapNonceSize : entryOff+entrySize]
			h := sha256.Sum256(append(wrapNonce, wrapped...))
			id := fmt.Sprintf("%02x%02x%02x%02x%02x%02x%02x%02x",
				h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7])
			fi.RecipientIDs = append(fi.RecipientIDs, id)
		}
	case algoPubKeyRSA:
		fi.NumRecipients = 1
		off := 0
		wrapLen := int(binary.BigEndian.Uint16(payload[off:]))
		off += 2
		wrapped := payload[off : off+wrapLen]
		h := sha256.Sum256(wrapped)
		fi.RecipientIDs = append(fi.RecipientIDs, fmt.Sprintf("%02x%02x%02x%02x%02x%02x%02x%02x",
			h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]))
	case algoPubKeyRSAMulti:
		off := 0
		off += saltLen
		off += aesNonceSize
		if off+entryHeadSize > len(payload) {
			return nil, ErrCorruptedData
		}
		numRecipients := int(payload[off])
		fi.NumRecipients = numRecipients
		off += entryHeadSize
		for i := 0; i < numRecipients; i++ {
			wrapLen := int(binary.BigEndian.Uint16(payload[off:]))
			off += 2
			wrapped := payload[off : off+wrapLen]
			off += wrapLen
			h := sha256.Sum256(wrapped)
			fi.RecipientIDs = append(fi.RecipientIDs, fmt.Sprintf("%02x%02x%02x%02x%02x%02x%02x%02x",
				h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]))
		}
	case algoPubKeyHybrid:
		off := 0
		off += pubKeyLen
		off += saltLen
		off += aesNonceSize
		if off+entryHeadSize > len(payload) {
			return nil, ErrCorruptedData
		}
		numRecipients := int(payload[off])
		fi.NumRecipients = numRecipients
		off += entryHeadSize
		for i := 0; i < numRecipients; i++ {
			entryType := payload[off]
			off++
			var wrapped []byte
			if entryType == 0 {
				off += wrapNonceSize
				wrapped = payload[off : off+wrappedContentSize]
				off += wrappedContentSize
			} else {
				wrapLen := int(binary.BigEndian.Uint16(payload[off:]))
				off += 2
				wrapped = payload[off : off+wrapLen]
				off += wrapLen
			}
			h := sha256.Sum256(wrapped)
			fi.RecipientIDs = append(fi.RecipientIDs, fmt.Sprintf("%02x%02x%02x%02x%02x%02x%02x%02x",
				h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]))
		}
	}

	return fi, nil
}

func kdfString(kdf byte) string {
	switch kdf {
	case kdfScrypt:
		return "scrypt"
	case kdfArgon2id:
		return "argon2id"
	case kdfECDH:
		return "hkdf-sha256"
	case kdfRSAOAEP:
		return "rsa-oaep"
	default:
		return "unknown"
	}
}

// VerifyKey verifies whether the password is correct for the given ciphertext.
func VerifyKey(password, data []byte) (bool, error) {
	_, _, err := Decrypt(password, data)
	if err != nil {
		return false, err
	}
	return true, nil
}

// Key management.

const (
	identityLabel = "GO-ENCRYPTOR-SECRET-KEY-1"
	pubKeyLen     = 32
)

// Identity holds an X25519 key pair.
type Identity struct {
	Label    string
	Seed     []byte // 32-byte seed (private key)
	Public   []byte // 32-byte public key
}

func (id *Identity) KeyType() KeyType    { return KeyTypeX25519 }
func (id *Identity) PublicBytes() []byte  { return id.Public }
func (id *Identity) PrivateBytes() []byte { return id.Seed }

// GenerateIdentity creates a new random X25519 identity.
func GenerateIdentity(comment string) (*Identity, error) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	seed := privateKey.Bytes()
	publicKey := privateKey.PublicKey()
	pubBytes := publicKey.Bytes()
	return &Identity{
		Label:  comment,
		Seed:   seed,
		Public: pubBytes,
	}, nil
}

// MarshalIdentity serializes an identity to a byte slice.
func MarshalIdentity(id *Identity) []byte {
	var buf bytes.Buffer
	buf.WriteString(identityLabel + "\n")
	if id.Label != "" {
		buf.WriteString("# " + id.Label + "\n")
	}
	buf.WriteString("# public: " + PublicKeyToRecipient(id.Public) + "\n")
	buf.WriteString(base64.StdEncoding.EncodeToString(id.Seed) + "\n")
	return buf.Bytes()
}

// UnmarshalIdentity parses an identity from a byte slice.
func UnmarshalIdentity(data []byte) (*Identity, error) {
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	var seedB64 []byte
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 || bytes.HasPrefix(line, []byte("#")) {
			continue
		}
		if bytes.HasPrefix(line, []byte(identityLabel)) {
			continue
		}
		seedB64 = line
	}
	if len(seedB64) == 0 {
		return nil, errors.New("invalid identity file: no seed found")
	}
	seed, err := base64.StdEncoding.DecodeString(string(seedB64))
	if err != nil {
		return nil, fmt.Errorf("invalid identity file: %w", err)
	}

	privateKey, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, fmt.Errorf("invalid identity file: %w", err)
	}
	pubBytes := privateKey.PublicKey().Bytes()

	return &Identity{
		Seed:   seed,
		Public: pubBytes,
	}, nil
}

// PublicKeyToRecipient returns the recipient string for a public key.
func PublicKeyToRecipient(pub []byte) string {
	return "goenc" + base64.RawStdEncoding.EncodeToString(pub)
}

// RecipientToPublicKey parses a goenc recipient string and returns a Recipient.
func RecipientToPublicKey(recipient string) (Recipient, error) {
	const prefix = "goenc"
	if len(recipient) < len(prefix) || recipient[:len(prefix)] != prefix {
		return nil, errors.New("invalid recipient format")
	}
	pub, err := base64.RawStdEncoding.DecodeString(recipient[len(prefix):])
	if err != nil {
		return nil, err
	}
	return newX25519Recipient(pub)
}

// NewX25519Recipient creates a Recipient from raw X25519 public key bytes.
func NewX25519Recipient(pub []byte) (Recipient, error) {
	return newX25519Recipient(pub)
}

const keyStoreLabelV2 = "GO-ENCRYPTOR-KEY-1"

type KeyStoreEntry struct {
	Type      KeyType
	Label     string
	Public    []byte
	Private   []byte
	CreatedAt int64
	Meta      map[string]string
}

func MarshalKeyStoreEntry(entry *KeyStoreEntry) []byte {
	var buf bytes.Buffer
	buf.WriteString(keyStoreLabelV2 + "\n")
	buf.WriteString("# type: " + entry.Type.String() + "\n")
	if entry.Label != "" {
		buf.WriteString("# label: " + entry.Label + "\n")
	}
	if entry.CreatedAt > 0 {
		buf.WriteString(fmt.Sprintf("# created: %d\n", entry.CreatedAt))
	}
	for k, v := range entry.Meta {
		buf.WriteString("# " + k + ": " + v + "\n")
	}
	buf.WriteString(base64.StdEncoding.EncodeToString(entry.Private) + "\n")
	return buf.Bytes()
}

func UnmarshalKeyStoreEntry(data []byte) (*KeyStoreEntry, error) {
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	entry := &KeyStoreEntry{
		Type: KeyTypeX25519,
		Meta: make(map[string]string),
	}
	var privB64 []byte
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		if bytes.HasPrefix(line, []byte(keyStoreLabelV2)) || bytes.HasPrefix(line, []byte(identityLabel)) {
			continue
		}
		if line[0] == '#' {
			rest := strings.TrimSpace(string(line[1:]))
			parts := strings.SplitN(rest, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				switch key {
				case "type":
					switch val {
					case "x25519":
						entry.Type = KeyTypeX25519
					case "rsa":
						entry.Type = KeyTypeRSA
					}
				case "label":
					entry.Label = val
				case "created":
					fmt.Sscanf(val, "%d", &entry.CreatedAt)
				default:
					entry.Meta[key] = val
				}
			}
			continue
		}
		privB64 = line
	}
	if len(privB64) == 0 {
		return nil, errors.New("invalid key: no private key data found")
	}
	privRaw, err := base64.StdEncoding.DecodeString(string(privB64))
	if err != nil {
		return nil, fmt.Errorf("invalid key: %w", err)
	}
	entry.Private = privRaw

	switch entry.Type {
	case KeyTypeX25519:
		privateKey, err := ecdh.X25519().NewPrivateKey(privRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid x25519 key: %w", err)
		}
		entry.Public = privateKey.PublicKey().Bytes()
	case KeyTypeRSA:
		privKey, err := x509.ParsePKCS8PrivateKey(privRaw)
		if err != nil {
			return nil, fmt.Errorf("invalid rsa key: %w", err)
		}
		rsaPriv, ok := privKey.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}
		pubBytes, err := x509.MarshalPKIXPublicKey(&rsaPriv.PublicKey)
		if err != nil {
			return nil, err
		}
		entry.Public = pubBytes
	default:
		return nil, fmt.Errorf("unsupported key type: %s", entry.Type)
	}

	return entry, nil
}

func EntryToPrivateKey(e *KeyStoreEntry) (PrivateKey, error) {
	switch e.Type {
	case KeyTypeX25519:
		return &x25519Identity{seed: e.Private, public: e.Public}, nil
	case KeyTypeRSA:
		priv, err := x509.ParsePKCS8PrivateKey(e.Private)
		if err != nil {
			return nil, err
		}
		rsaPriv, ok := priv.(*rsa.PrivateKey)
		if !ok {
			return nil, errors.New("not an RSA private key")
		}
		return &rsaIdentity{priv: rsaPriv, public: e.Public}, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %s", e.Type)
	}
}

func IdentityFromRSA(priv *rsa.PrivateKey, label string) (*KeyStoreEntry, error) {
	privRaw, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pubBytes, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, err
	}
	return &KeyStoreEntry{
		Type:    KeyTypeRSA,
		Label:   label,
		Public:  pubBytes,
		Private: privRaw,
	}, nil
}

func RecipientFromRSA(pub *rsa.PublicKey) *rsaRecipient {
	return &rsaRecipient{pub: pub}
}

// pubKeyEncrypt encrypts data to a recipient's public key using X25519 ECDH
// + HKDF + AES-GCM. Returns v2-format ciphertext with algo=pubKey.
func pubKeyEncrypt(recipientPub []byte, data []byte, ext string) ([]byte, error) {
	pubKey, err := ecdh.X25519().NewPublicKey(recipientPub)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient public key: %w", err)
	}

	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ephemeralPub := ephemeral.PublicKey().Bytes()

	sharedSecret, err := ephemeral.ECDH(pubKey)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(sharedSecret)

	// Derive AES key via HKDF.
	salt := make([]byte, saltLen)
	rand.Read(salt)
	hkdf := hkdf.New(sha256.New, sharedSecret, salt, []byte("go-encryptor-v2"))
	aesKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, aesKey); err != nil {
		return nil, err
	}
	defer zeroBytes(aesKey)

	blockCipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	masterNonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(masterNonce); err != nil {
		return nil, err
	}

	h := &fileHeader{algo: algoPubKey, kdf: kdfECDH, ext: ext}
	header := h.marshal()

	var buf bytes.Buffer
	buf.Write(header)
	buf.Write(ephemeralPub)
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

// pubKeyDecrypt decrypts data encrypted to a public key using the private seed.
// Supports both single-recipient (algo=2) and multi-recipient (algo=3) formats.
func pubKeyDecrypt(seed []byte, data []byte) ([]byte, string, error) {
	privateKey, err := ecdh.X25519().NewPrivateKey(seed)
	if err != nil {
		return nil, "", err
	}

	hdr, hdrLen, err := parseHeader(data)
	if err != nil {
		return nil, "", err
	}
	if hdr.algo != algoPubKey && hdr.algo != algoPubKeyMulti {
		return nil, "", ErrUnsupportedAlgo
	}
	payload := data[hdrLen:]

	// Single-recipient format (backward compatible).
	if hdr.algo == algoPubKey {
		if len(payload) < pubKeyLen+saltLen+aesNonceSize {
			return nil, "", ErrCorruptedData
		}
		ephemeralPub := payload[:pubKeyLen]
		salt := payload[pubKeyLen : pubKeyLen+saltLen]
		masterNonce := payload[pubKeyLen+saltLen : pubKeyLen+saltLen+aesNonceSize]
		chunkData := payload[pubKeyLen+saltLen+aesNonceSize:]

		ephemeralKey, err := ecdh.X25519().NewPublicKey(ephemeralPub)
		if err != nil {
			return nil, "", err
		}
		sharedSecret, err := privateKey.ECDH(ephemeralKey)
		if err != nil {
			return nil, "", err
		}
		defer zeroBytes(sharedSecret)
		hkdf := hkdf.New(sha256.New, sharedSecret, salt, []byte("go-encryptor-v2"))
		aesKey := make([]byte, 32)
		if _, err := io.ReadFull(hkdf, aesKey); err != nil {
			return nil, "", err
		}
		defer zeroBytes(aesKey)
		blockCipher, err := aes.NewCipher(aesKey)
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

	// Multi-recipient format.
	if len(payload) < pubKeyLen+saltLen+aesNonceSize+entryHeadSize {
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
	off += entryHeadSize

	// Derive our wrapping key.
	ephemeralKey, err := ecdh.X25519().NewPublicKey(ephemeralPub)
	if err != nil {
		return nil, "", err
	}
	sharedSecret, err := privateKey.ECDH(ephemeralKey)
	if err != nil {
		return nil, "", err
	}
	defer zeroBytes(sharedSecret)
	hkdf := hkdf.New(sha256.New, sharedSecret, salt, []byte("go-encryptor-multi"))
	wrapKey := make([]byte, 32)
	if _, err := io.ReadFull(hkdf, wrapKey); err != nil {
		return nil, "", err
	}
	defer zeroBytes(wrapKey)
	blockCipher, err := aes.NewCipher(wrapKey)
	if err != nil {
		return nil, "", err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, "", err
	}

	// Try each wrapped content key entry.
	entrySize := wrapNonceSize + wrappedContentSize
	if off+numRecipients*entrySize > len(payload) {
		return nil, "", ErrCorruptedData
	}
	var contentKey []byte
	for i := 0; i < numRecipients; i++ {
		entryOff := off + i*entrySize
		wrapNonce := payload[entryOff : entryOff+wrapNonceSize]
		wrapped := payload[entryOff+wrapNonceSize : entryOff+entrySize]
		ck, err := gcm.Open(nil, wrapNonce, wrapped, nil)
		if err == nil {
			contentKey = ck
			break
		}
	}
	if contentKey == nil {
		return nil, "", ErrWrongPassword
	}

	// Decrypt chunked data with content key.
	chunkOff := off + numRecipients*(wrapNonceSize+wrappedContentSize)
	chunkData := payload[chunkOff:]

	dataBlock, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, "", err
	}
	dataGCM, err := cipher.NewGCM(dataBlock)
	if err != nil {
		return nil, "", err
	}

	var plaintext bytes.Buffer
	r := bytes.NewReader(chunkData)
	var idx uint32
	for {
		pt, err := readChunk(r, dataGCM, dataNonce, idx)
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

// EncryptToPublicKey encrypts data to a single recipient.
// Auto-detects algorithm from key type.
func EncryptToPublicKey(recipient Recipient, data []byte, ext string) ([]byte, error) {
	return EncryptToPublicKeys([]Recipient{recipient}, data, ext)
}

// EncryptToPublicKeys encrypts data to one or more recipients.
// Auto-detects algorithm from key types (X25519 only, RSA only, or hybrid).
func EncryptToPublicKeys(recipients []Recipient, data []byte, ext string) ([]byte, error) {
	if len(recipients) == 0 {
		return nil, errors.New("at least one recipient required")
	}

	hasX25519 := false
	hasRSA := false
	for _, r := range recipients {
		switch r.KeyType() {
		case KeyTypeX25519:
			hasX25519 = true
		case KeyTypeRSA:
			hasRSA = true
		}
	}

	switch {
	case hasX25519 && !hasRSA && len(recipients) == 1:
		xr, ok := recipients[0].(*x25519Recipient)
		if !ok {
			return nil, errors.New("unexpected recipient type for X25519 key")
		}
		return pubKeyEncrypt(xr.pub.Bytes(), data, ext)
	case hasX25519 && !hasRSA && len(recipients) > 1:
		pubs := make([][]byte, len(recipients))
		for i, r := range recipients {
			xr, ok := r.(*x25519Recipient)
			if !ok {
				return nil, fmt.Errorf("unexpected recipient type for X25519 key at index %d", i)
			}
			pubs[i] = xr.pub.Bytes()
		}
		return pubKeyMultiEncrypt(pubs, data, ext)
	case !hasX25519 && hasRSA && len(recipients) == 1:
		rr, ok := recipients[0].(*rsaRecipient)
		if !ok {
			return nil, errors.New("unexpected recipient type for RSA key")
		}
		return rsaSingleEncrypt(rr.pub, data, ext)
	case !hasX25519 && hasRSA && len(recipients) > 1:
		pubs := make([]*rsa.PublicKey, len(recipients))
		for i, r := range recipients {
			rr, ok := r.(*rsaRecipient)
			if !ok {
				return nil, fmt.Errorf("unexpected recipient type for RSA key at index %d", i)
			}
			pubs[i] = rr.pub
		}
		return rsaMultiEncrypt(pubs, data, ext)
	default:
		return hybridEncrypt(recipients, data, ext)
	}
}

// DecryptWithIdentity decrypts data using a private key.
// Supports X25519 (algoPubKey/algoPubKeyMulti), RSA (algoPubKeyRSA/algoPubKeyRSAMulti),
// and hybrid (algoPubKeyHybrid) formats.
func DecryptWithIdentity(priv PrivateKey, data []byte) ([]byte, string, error) {
	hdr, _, err := parseHeader(data)
	if err != nil {
		return nil, "", err
	}

	switch hdr.algo {
	case algoPubKey, algoPubKeyMulti:
		var seed []byte
		switch k := priv.(type) {
		case *Identity:
			seed = k.Seed
		case *x25519Identity:
			seed = k.seed
		default:
			return nil, "", errors.New("X25519 private key required for ECDH decryption")
		}
		return pubKeyDecrypt(seed, data)
	case algoPubKeyRSA:
		rsaPriv, ok := priv.(*rsaIdentity)
		if !ok {
			return nil, "", errors.New("RSA private key required for RSA decryption")
		}
		return rsaSingleDecrypt(rsaPriv.priv, data)
	case algoPubKeyRSAMulti:
		rsaPriv, ok := priv.(*rsaIdentity)
		if !ok {
			return nil, "", errors.New("RSA private key required for RSA decryption")
		}
		return rsaMultiDecrypt(rsaPriv.priv, data)
	case algoPubKeyHybrid:
		return hybridDecrypt(priv, data)
	default:
		return nil, "", ErrUnsupportedAlgo
	}
}

// pubKeyMultiEncrypt encrypts data to multiple X25519 recipients using a wrapped content key.
func pubKeyMultiEncrypt(recipientPubs [][]byte, data []byte, ext string) ([]byte, error) {
	if len(recipientPubs) == 0 {
		return nil, errors.New("at least one recipient required")
	}
	if len(recipientPubs) == 1 {
		return pubKeyEncrypt(recipientPubs[0], data, ext)
	}

	ephemeral, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	ephemeralPub := ephemeral.PublicKey().Bytes()

	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	contentKey := make([]byte, contentKeySize)
	if _, err := rand.Read(contentKey); err != nil {
		return nil, err
	}
	defer zeroBytes(contentKey)
	dataNonce := make([]byte, aesNonceSize)
	if _, err := rand.Read(dataNonce); err != nil {
		return nil, err
	}

	var entriesBuf bytes.Buffer
	entriesBuf.WriteByte(byte(len(recipientPubs)))
	for _, pub := range recipientPubs {
		pubKey, err := ecdh.X25519().NewPublicKey(pub)
		if err != nil {
			return nil, fmt.Errorf("invalid recipient public key: %w", err)
		}
		sharedSecret, err := ephemeral.ECDH(pubKey)
		if err != nil {
			return nil, err
		}
		hkdf := hkdf.New(sha256.New, sharedSecret, salt, []byte("go-encryptor-multi"))
		wrapKey := make([]byte, 32)
		if _, err := io.ReadFull(hkdf, wrapKey); err != nil {
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
	}

	blockCipher, err := aes.NewCipher(contentKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		return nil, err
	}

	h := &fileHeader{algo: algoPubKeyMulti, kdf: kdfECDH, ext: ext}
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

// Backward-compatible per-algorithm functions (kept for tests and migration).

// AESEncrypt encrypts with AES-256-GCM, returns v2-format ciphertext.
func AESEncrypt(key, data []byte) ([]byte, error) {
	return aesEncryptV2(key, data, "")
}

// AESDecrypt decrypts AES ciphertext (auto-detects v1/v2).
func AESDecrypt(key, data []byte) ([]byte, error) {
	plaintext, _, err := Decrypt(key, data)
	return plaintext, err
}

// AESVerifyKey verifies an AES-encrypted password.
func AESVerifyKey(key, data []byte) (bool, error) {
	return VerifyKey(key, data)
}

// ChaCha20Encrypt encrypts with XChaCha20-Poly1305, returns v2-format ciphertext.
func ChaCha20Encrypt(key, data []byte) ([]byte, error) {
	return chachaEncryptV2(key, data, "")
}

// ChaCha20Decrypt decrypts ChaCha20 ciphertext (auto-detects v1/v2).
func ChaCha20Decrypt(key, data []byte) ([]byte, error) {
	plaintext, _, err := Decrypt(key, data)
	return plaintext, err
}

// ChaCha20VerifyKey verifies a ChaCha20-encrypted password.
func ChaCha20VerifyKey(key, data []byte) (bool, error) {
	return VerifyKey(key, data)
}
