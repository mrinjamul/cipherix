package crypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"encoding/pem"
	"strings"
	"testing"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/scrypt"
	"golang.org/x/crypto/ssh"
)

func TestDeriveKey(t *testing.T) {
	password := []byte("password")
	salt := make([]byte, saltLen)
	key, err := deriveKeyAES(password, salt)
	if len(key) == 0 {
		t.Errorf("Want key but got nil")
	}
	if err != nil {
		t.Errorf("Want nil but got errors, %v", err)
	}
}

func TestAESEncrypt(t *testing.T) {
	password := []byte("password")
	data := []byte("Data")
	cipherdata, err := AESEncrypt(password, data)
	if cipherdata == nil {
		t.Errorf("Want strings but got nil")
	}
	if err != nil {
		t.Errorf("Want nil but got errors")
	}
}

func TestAESDecrypt(t *testing.T) {
	password := []byte("password")
	data := []byte("Data")
	cipherdata, _ := AESEncrypt(password, data)
	plaindata, err := AESDecrypt(password, cipherdata)
	if plaindata == nil {
		t.Errorf("Want strings but got nil")
	}
	if err != nil {
		t.Errorf("Want nil but got errors")
	}
}

func TestAESVerifyKey(t *testing.T) {
	password := []byte("password")
	fakepassword := []byte("fakepassword")
	data := []byte("Data")
	cipherdata, _ := AESEncrypt(password, data)
	res, err := AESVerifyKey(password, cipherdata)
	if err != nil {
		t.Errorf("Want erors to be nil but got %v\n", err)
	}
	if res != true {
		t.Errorf("Want true but got false")
	}
	res, err = AESVerifyKey(fakepassword, cipherdata)
	if err == nil {
		t.Errorf("Want erors but got nil")
	}
	if res != false {
		t.Errorf("Want false but got true")
	}
}

func TestChaCha20Encrypt(t *testing.T) {
	password := []byte("password")
	data := []byte("Data")
	cipherdata, err := ChaCha20Encrypt(password, data)
	if cipherdata == nil {
		t.Errorf("Want strings but got nil")
	}
	if err != nil {
		t.Errorf("Want nil but got errors")
	}
}

func TestChaCha20Decrypt(t *testing.T) {
	password := []byte("password")
	data := []byte("Data")
	cipherdata, _ := ChaCha20Encrypt(password, data)
	plaindata, err := ChaCha20Decrypt(password, cipherdata)
	if plaindata == nil {
		t.Errorf("Want strings but got nil")
	}
	if err != nil {
		t.Errorf("Want nil but got errors")
	}
}

func TestChaCha20VerifyKey(t *testing.T) {
	password := []byte("password")
	fakepassword := []byte("fakepassword")
	data := []byte("Data")
	cipherdata, _ := ChaCha20Encrypt(password, data)
	res, err := ChaCha20VerifyKey(password, cipherdata)
	if err != nil {
		t.Errorf("Want erors to be nil but got %v\n", err)
	}
	if res != true {
		t.Errorf("Want true but got false")
	}
	res, err = ChaCha20VerifyKey(fakepassword, cipherdata)
	if err == nil {
		t.Errorf("Want erors but got nil")
	}
	if res != false {
		t.Errorf("Want false but got true")
	}
}

func TestEncryptDispatch(t *testing.T) {
	password := []byte("testpassword123")
	data := []byte("hello world")

	// AES routing.
	cipherdata, err := Encrypt(password, data, "aes", "txt")
	if err != nil {
		t.Fatalf("AES Encrypt failed: %v", err)
	}
	plaintext, ext, err := Decrypt(password, cipherdata)
	if err != nil || string(plaintext) != string(data) || ext != "txt" {
		t.Fatalf("AES roundtrip failed: err=%v, ext=%q", err, ext)
	}

	// ChaCha20 routing.
	cipherdata, err = Encrypt(password, data, "chacha20", "dat")
	if err != nil {
		t.Fatalf("ChaCha20 Encrypt failed: %v", err)
	}
	plaintext, ext, err = Decrypt(password, cipherdata)
	if err != nil || string(plaintext) != string(data) || ext != "dat" {
		t.Fatalf("ChaCha20 roundtrip failed: err=%v, ext=%q", err, ext)
	}

	// Invalid algorithm.
	_, err = Encrypt(password, data, "invalid", "")
	if err != ErrUnsupportedAlgo {
		t.Fatalf("expected ErrUnsupportedAlgo, got %v", err)
	}
}

func TestDecryptDetectsV2(t *testing.T) {
	password := []byte("testpw")
	data := []byte("data to encrypt")

	cipherdata, err := Encrypt(password, data, "aes", "bin")
	if err != nil {
		t.Fatal(err)
	}

	plaintext, ext, err := Decrypt(password, cipherdata)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if string(plaintext) != string(data) {
		t.Fatalf("plaintext mismatch: got %q, want %q", string(plaintext), string(data))
	}
	if ext != "bin" {
		t.Fatalf("ext mismatch: got %q, want %q", ext, "bin")
	}
}

func TestEncryptDecryptAllAlgorithms(t *testing.T) {
	tests := []struct {
		name      string
		algorithm string
	}{
		{"AES", "aes"},
		{"ChaCha20", "chacha20"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			password := []byte("password123")
			data := []byte("some sensitive data")
			cipherdata, err := Encrypt(password, data, tc.algorithm, "sec")
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}
			plaintext, ext, err := Decrypt(password, cipherdata)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}
			if string(plaintext) != string(data) {
				t.Fatalf("plaintext mismatch")
			}
			if ext != "sec" {
				t.Fatalf("ext mismatch: got %q", ext)
			}
		})
	}
}

func TestV1AESBackwardCompat(t *testing.T) {
	password := []byte("v1testpassword")
	plaintext := []byte("this is v1 format data")
	ext := "txt"

	salt := make([]byte, saltLen)
	rand.Read(salt)
	dk, err := scrypt.Key(password, salt, 1<<16, 8, 1, 32)
	if err != nil {
		t.Fatal(err)
	}
	block, err := aes.NewCipher(dk)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	rand.Read(nonce)

	ptWithExt := append(plaintext, []byte(ext)...)
	ciphertext := gcm.Seal(nil, nonce, ptWithExt, nil)

	var v1Buf []byte
	v1Buf = append(v1Buf, nonce...)
	v1Buf = append(v1Buf, ciphertext...)
	v1Buf = append(v1Buf, salt...)

	result, gotExt, err := Decrypt(password, v1Buf)
	if err != nil {
		t.Fatalf("v1 AES decrypt failed: %v", err)
	}
	if string(result) != string(plaintext) {
		t.Fatalf("v1 AES plaintext mismatch: got %q, want %q", string(result), string(plaintext))
	}
	if gotExt != ext {
		t.Fatalf("v1 AES ext mismatch: got %q, want %q", gotExt, ext)
	}
}

func TestV1ChaCha20BackwardCompat(t *testing.T) {
	password := []byte("v1chachapass")
	plaintext := []byte("v1 chacha20 data")
	ext := "dat"

	salt := make([]byte, saltLen)
	rand.Read(salt)
	dk := deriveKeyChaCha(password, salt)
	aead, err := chacha20poly1305.NewX(dk)
	if err != nil {
		t.Fatal(err)
	}
	nonce := make([]byte, aead.NonceSize())
	rand.Read(nonce)

	ptWithExt := append(plaintext, []byte(ext)...)
	ciphertext := aead.Seal(nil, nonce, ptWithExt, nil)

	var v1Buf []byte
	v1Buf = append(v1Buf, ciphertext...)
	v1Buf = append(v1Buf, salt...)
	v1Buf = append(v1Buf, nonce...)

	result, gotExt, err := Decrypt(password, v1Buf)
	if err != nil {
		t.Fatalf("v1 ChaCha20 decrypt failed: %v", err)
	}
	if string(result) != string(plaintext) {
		t.Fatalf("v1 ChaCha20 plaintext mismatch: got %q, want %q", string(result), string(plaintext))
	}
	if gotExt != ext {
		t.Fatalf("v1 ChaCha20 ext mismatch: got %q, want %q", gotExt, ext)
	}
}

func TestV1FallbackOrder(t *testing.T) {
	password := []byte("test")
	salt := make([]byte, saltLen)
	rand.Read(salt)
	dk, _ := scrypt.Key(password, salt, 1<<16, 8, 1, 32)
	block, _ := aes.NewCipher(dk)
	gcm, _ := cipher.NewGCM(block)
	nonce := make([]byte, 12)
	rand.Read(nonce)
	pt := append([]byte("fallback test"), []byte("ext")...)
	ct := gcm.Seal(nil, nonce, pt, nil)

	var v1Buf []byte
	v1Buf = append(v1Buf, nonce...)
	v1Buf = append(v1Buf, ct...)
	v1Buf = append(v1Buf, salt...)

	result, ext, err := Decrypt(password, v1Buf)
	if err != nil {
		t.Fatalf("v1 fallback AES failed: %v", err)
	}
	if string(result) != "fallback test" || ext != "ext" {
		t.Fatalf("AES v1 fallback: got %q / %q", string(result), ext)
	}
}

func TestStreamEncryptDecryptAES(t *testing.T) {
	password := []byte("streamtest")
	plaintext := []byte("hello from streaming api")

	var buf bytes.Buffer
	written, err := StreamEncrypt(password, bytes.NewReader(plaintext), &buf, "aes", "str")
	if err != nil {
		t.Fatalf("StreamEncrypt AES failed: %v", err)
	}
	if written <= 0 {
		t.Fatalf("expected >0 bytes written, got %d", written)
	}

	var result bytes.Buffer
	ext, err := StreamDecrypt(password, bytes.NewReader(buf.Bytes()), &result)
	if err != nil {
		t.Fatalf("StreamDecrypt AES failed: %v", err)
	}
	if ext != "str" {
		t.Fatalf("ext mismatch: got %q, want %q", ext, "str")
	}
	if result.String() != string(plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", result.String(), string(plaintext))
	}
}

func TestStreamEncryptDecryptChaCha20(t *testing.T) {
	password := []byte("chachastream")
	plaintext := []byte("chacha streaming test")

	var buf bytes.Buffer
	written, err := StreamEncrypt(password, bytes.NewReader(plaintext), &buf, "chacha20", "ch2")
	if err != nil {
		t.Fatalf("StreamEncrypt ChaCha20 failed: %v", err)
	}
	if written <= 0 {
		t.Fatalf("expected >0 bytes written, got %d", written)
	}

	var result bytes.Buffer
	ext, err := StreamDecrypt(password, bytes.NewReader(buf.Bytes()), &result)
	if err != nil {
		t.Fatalf("StreamDecrypt ChaCha20 failed: %v", err)
	}
	if ext != "ch2" {
		t.Fatalf("ext mismatch: got %q", ext)
	}
	if result.String() != string(plaintext) {
		t.Fatalf("plaintext mismatch")
	}
}

func TestStreamEncryptDecryptLarge(t *testing.T) {
	password := []byte("largestream")
	plaintext := make([]byte, 1024*1024) // 1 MiB
	rand.Read(plaintext)

	var buf bytes.Buffer
	_, err := StreamEncrypt(password, bytes.NewReader(plaintext), &buf, "aes", "big")
	if err != nil {
		t.Fatalf("StreamEncrypt large failed: %v", err)
	}

	var result bytes.Buffer
	_, err = StreamDecrypt(password, bytes.NewReader(buf.Bytes()), &result)
	if err != nil {
		t.Fatalf("StreamDecrypt large failed: %v", err)
	}
	if !bytes.Equal(result.Bytes(), plaintext) {
		t.Fatalf("large stream plaintext mismatch (%d vs %d bytes)", len(result.Bytes()), len(plaintext))
	}
}

func TestStreamDecryptWrongPassword(t *testing.T) {
	password := []byte("correct")
	wrong := []byte("wrong")
	data := []byte("test data")

	var buf bytes.Buffer
	StreamEncrypt(password, bytes.NewReader(data), &buf, "aes", "")

	var result bytes.Buffer
	_, err := StreamDecrypt(wrong, bytes.NewReader(buf.Bytes()), &result)
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestStreamEncryptUnsupportedAlgo(t *testing.T) {
	_, err := StreamEncrypt([]byte("pw"), nil, nil, "invalid", "")
	if err != ErrUnsupportedAlgo {
		t.Fatalf("expected ErrUnsupportedAlgo, got %v", err)
	}
}

func TestInspect(t *testing.T) {
	password := []byte("inspectpw")
	data := []byte("inspectable data")

	cipherdata, err := Encrypt(password, data, "aes", "xyz")
	if err != nil {
		t.Fatal(err)
	}

	algo, ext, err := Inspect(cipherdata)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if algo != "aes" {
		t.Fatalf("algo mismatch: got %q, want %q", algo, "aes")
	}
	if ext != "xyz" {
		t.Fatalf("ext mismatch: got %q, want %q", ext, "xyz")
	}

	cipherdata2, _ := Encrypt(password, data, "chacha20", "abc")
	algo2, ext2, _ := Inspect(cipherdata2)
	if algo2 != "chacha20" || ext2 != "abc" {
		t.Fatalf("chacha20 inspect: got %q / %q", algo2, ext2)
	}
}

func TestInspectV2Only(t *testing.T) {
	_, _, err := Inspect([]byte("not-a-header"))
	if err == nil {
		t.Fatal("expected error for non-v2 data")
	}
}

func TestVerifyKey(t *testing.T) {
	password := []byte("verifypw")
	data := []byte("verify test")

	cipherdata, _ := Encrypt(password, data, "aes", "")

	ok, err := VerifyKey(password, cipherdata)
	if err != nil {
		t.Fatalf("VerifyKey failed: %v", err)
	}
	if !ok {
		t.Fatal("expected true for correct password")
	}

	ok, err = VerifyKey([]byte("wrong"), cipherdata)
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
	if ok {
		t.Fatal("expected false for wrong password")
	}
}

func TestGenerateIdentity(t *testing.T) {
	id, err := GenerateIdentity("test-identity")
	if err != nil {
		t.Fatalf("GenerateIdentity failed: %v", err)
	}
	if id == nil {
		t.Fatal("expected non-nil identity")
	}
	if len(id.Seed) != 32 {
		t.Fatalf("expected 32-byte seed, got %d", len(id.Seed))
	}
	if len(id.Public) != 32 {
		t.Fatalf("expected 32-byte public key, got %d", len(id.Public))
	}
	if id.Label != "test-identity" {
		t.Fatalf("label mismatch: got %q", id.Label)
	}
}

func TestMarshalUnmarshalIdentity(t *testing.T) {
	id, err := GenerateIdentity("my-comment")
	if err != nil {
		t.Fatal(err)
	}

	data := MarshalIdentity(id)
	if len(data) == 0 {
		t.Fatal("expected non-empty marshal output")
	}
	if !strings.HasPrefix(string(data), identityLabel) {
		t.Fatalf("expected label prefix, got %q", string(data[:20]))
	}
	if !strings.Contains(string(data), "# public: cphx") {
		t.Fatalf("expected public key comment, got %q", string(data))
	}

	id2, err := UnmarshalIdentity(data)
	if err != nil {
		t.Fatalf("UnmarshalIdentity failed: %v", err)
	}
	if !bytes.Equal(id.Seed, id2.Seed) {
		t.Fatal("seed mismatch after marshal/unmarshal")
	}
	if !bytes.Equal(id.Public, id2.Public) {
		t.Fatal("public key mismatch after marshal/unmarshal")
	}
}

func TestUnmarshalIdentityInvalid(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"empty", []byte{}},
		{"no seed", []byte(identityLabel + "\n# comment\n")},
		{"invalid base64", []byte(identityLabel + "\n!!!not-base64!!!\n")},
		{"short seed", []byte(identityLabel + "\n" + "YWJj\n")}, // "abc" = 3 bytes, not 32
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := UnmarshalIdentity(tc.data)
			if err == nil {
				t.Fatal("expected error for invalid identity")
			}
		})
	}
}

func TestPublicKeyToRecipientRoundtrip(t *testing.T) {
	id, err := GenerateIdentity("")
	if err != nil {
		t.Fatal(err)
	}

	recipient := PublicKeyToRecipient(id.Public)
	if !strings.HasPrefix(recipient, "cphx") {
		t.Fatalf("expected cphx prefix, got %q", recipient)
	}

	pubKey, err := RecipientToPublicKey(recipient)
	if err != nil {
		t.Fatalf("RecipientToPublicKey failed: %v", err)
	}
	if !bytes.Equal(pubKey.PublicBytes(), id.Public) {
		t.Fatal("public key roundtrip mismatch")
	}
}

func TestRecipientToPublicKeyInvalid(t *testing.T) {
	_, err := RecipientToPublicKey("invalid")
	if err == nil {
		t.Fatal("expected error for invalid recipient")
	}
	_, err = RecipientToPublicKey("cphx!!!invalid-base64!!!")
	if err == nil {
		t.Fatal("expected error for invalid base64 recipient")
	}
}

func TestEncryptDecryptToPublicKey(t *testing.T) {
	id, err := GenerateIdentity("")
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("pubkey encrypted secret")
	ext := "sec"

	recip, err := NewX25519Recipient(id.Public)
	if err != nil {
		t.Fatal(err)
	}
	cipherdata, err := EncryptToPublicKey(recip, plaintext, ext)
	if err != nil {
		t.Fatalf("EncryptToPublicKey failed: %v", err)
	}
	if len(cipherdata) == 0 {
		t.Fatal("expected non-empty ciphertext")
	}

	result, gotExt, err := DecryptWithIdentity(id, cipherdata)
	if err != nil {
		t.Fatalf("DecryptWithIdentity failed: %v", err)
	}
	if !bytes.Equal(result, plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", string(result), string(plaintext))
	}
	if gotExt != ext {
		t.Fatalf("ext mismatch: got %q, want %q", gotExt, ext)
	}
}

func TestDecryptWithIdentityWrongKey(t *testing.T) {
	id1, _ := GenerateIdentity("")
	id2, _ := GenerateIdentity("")
	data := []byte("secret")

	recip, _ := NewX25519Recipient(id1.Public)
	cipherdata, _ := EncryptToPublicKey(recip, data, "")

	_, _, err := DecryptWithIdentity(id2, cipherdata)
	if err == nil {
		t.Fatal("expected error decrypting with wrong identity")
	}
}

func TestEncryptToMultiplePublicKeys(t *testing.T) {
	id1, err := GenerateIdentity("")
	if err != nil {
		t.Fatal(err)
	}
	id2, err := GenerateIdentity("")
	if err != nil {
		t.Fatal(err)
	}

	plaintext := []byte("multi-recipient secret data")
	ext := "multi"

	recip1, _ := NewX25519Recipient(id1.Public)
	recip2, _ := NewX25519Recipient(id2.Public)
	cipherdata, err := EncryptToPublicKeys([]Recipient{recip1, recip2}, plaintext, ext)
	if err != nil {
		t.Fatalf("EncryptToPublicKeys failed: %v", err)
	}
	if len(cipherdata) == 0 {
		t.Fatal("expected non-empty ciphertext")
	}

	// Both recipients should be able to decrypt.
	for i, id := range []PrivateKey{id1, id2} {
		result, gotExt, err := DecryptWithIdentity(id, cipherdata)
		if err != nil {
			t.Fatalf("recipient %d DecryptWithIdentity failed: %v", i+1, err)
		}
		if !bytes.Equal(result, plaintext) {
			t.Fatalf("recipient %d plaintext mismatch: got %q, want %q", i+1, string(result), string(plaintext))
		}
		if gotExt != ext {
			t.Fatalf("recipient %d ext mismatch: got %q, want %q", i+1, gotExt, ext)
		}
	}
}

func TestMultiRecipientNonRecipientFails(t *testing.T) {
	id1, _ := GenerateIdentity("")
	id2, _ := GenerateIdentity("")
	nonRecipient, _ := GenerateIdentity("")

	recip1, _ := NewX25519Recipient(id1.Public)
	recip2, _ := NewX25519Recipient(id2.Public)
	plaintext := []byte("secret for id1 and id2 only")
	cipherdata, err := EncryptToPublicKeys([]Recipient{recip1, recip2}, plaintext, "")
	if err != nil {
		t.Fatal(err)
	}

	// Non-recipient should not be able to decrypt.
	_, _, err = DecryptWithIdentity(nonRecipient, cipherdata)
	if err == nil {
		t.Fatal("expected error for non-recipient")
	}
}

func TestMultiRecipientSingleRecipient(t *testing.T) {
	// EncryptToPublicKeys with a single recipient should fall back to single format.
	id, _ := GenerateIdentity("")
	plaintext := []byte("single via multi function")

	recip, _ := NewX25519Recipient(id.Public)
	cipherdata, err := EncryptToPublicKeys([]Recipient{recip}, plaintext, "single")
	if err != nil {
		t.Fatal(err)
	}

	result, ext, err := DecryptWithIdentity(id, cipherdata)
	if err != nil {
		t.Fatalf("decrypt failed: %v", err)
	}
	if !bytes.Equal(result, plaintext) {
		t.Fatalf("plaintext mismatch: got %q, want %q", string(result), string(plaintext))
	}
	if ext != "single" {
		t.Fatalf("ext mismatch: got %q, want %q", ext, "single")
	}
}

func TestMultiRecipientEmptyData(t *testing.T) {
	id1, _ := GenerateIdentity("")
	id2, _ := GenerateIdentity("")

	recip1, _ := NewX25519Recipient(id1.Public)
	recip2, _ := NewX25519Recipient(id2.Public)
	cipherdata, err := EncryptToPublicKeys([]Recipient{recip1, recip2}, []byte{}, "")
	if err != nil {
		t.Fatalf("EncryptToPublicKeys with empty data failed: %v", err)
	}

	result, _, err := DecryptWithIdentity(id1, cipherdata)
	if err != nil {
		t.Fatalf("decrypt empty data failed: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected empty result, got %d bytes", len(result))
	}
}

func TestEncryptToPublicKeyWrongPubKey(t *testing.T) {
	_, err := NewX25519Recipient([]byte("short"))
	if err == nil {
		t.Fatal("expected error for invalid public key")
	}
}

func TestDecryptV2CorruptedData(t *testing.T) {
	password := []byte("pw")
	data := []byte("test")
	cipherdata, _ := Encrypt(password, data, "aes", "")

	corrupted := append([]byte{}, cipherdata...)
	corrupted[len(corrupted)-10] ^= 0xff

	_, _, err := Decrypt(password, corrupted)
	if err == nil {
		t.Fatal("expected error for corrupted data")
	}
}

func FuzzDecrypt(f *testing.F) {
	f.Add([]byte("password"), []byte("malformed-data"))
	f.Fuzz(func(t *testing.T, password, data []byte) {
		Decrypt(password, data)
	})
}

func FuzzParseHeader(f *testing.F) {
	f.Add([]byte("not-a-header"))
	f.Fuzz(func(t *testing.T, data []byte) {
		parseHeader(data)
	})
}

func FuzzUnmarshalIdentity(f *testing.F) {
	f.Add([]byte("invalid-identity-data"))
	f.Fuzz(func(t *testing.T, data []byte) {
		UnmarshalIdentity(data)
	})
}

func TestEncryptDecryptXChaCha20(t *testing.T) {
	password := []byte("testpassword123")
	data := []byte("hello xchacha20")

	cipherdata, err := Encrypt(password, data, "xchacha20", "xxx")
	if err != nil {
		t.Fatalf("xchacha20 Encrypt failed: %v", err)
	}
	plaintext, ext, err := Decrypt(password, cipherdata)
	if err != nil {
		t.Fatalf("xchacha20 Decrypt failed: %v", err)
	}
	if string(plaintext) != string(data) {
		t.Fatalf("plaintext mismatch: got %q, want %q", string(plaintext), string(data))
	}
	if ext != "xxx" {
		t.Fatalf("ext mismatch: got %q, want %q", ext, "xxx")
	}
}

func TestStreamDecryptWrongPasswordChaCha20(t *testing.T) {
	password := []byte("correct")
	wrong := []byte("wrong")
	data := []byte("chacha stream test")

	var buf bytes.Buffer
	_, err := StreamEncrypt(password, bytes.NewReader(data), &buf, "chacha20", "")
	if err != nil {
		t.Fatal(err)
	}

	var result bytes.Buffer
	_, err = StreamDecrypt(wrong, bytes.NewReader(buf.Bytes()), &result)
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
}

func TestIsV2FormatEdgeCases(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{"empty", []byte{}, false},
		{"4 bytes", []byte("goen"), false},
		{"exact magic", []byte("cphx"), true},
		{"longer magic", []byte("cphxx"), true},
		{"old magic", []byte("goenc"), true},
		{"no magic", []byte("hello"), false},
		{"partial magic", []byte("cph"), false},
		{"old partial", []byte("goe"), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := isV2Format(tc.data)
			if got != tc.want {
				t.Fatalf("isV2Format(%q) = %v, want %v", tc.data, got, tc.want)
			}
		})
	}
}

func TestDeriveNonce(t *testing.T) {
	master := make([]byte, 12)
	for i := range master {
		master[i] = 0xaa
	}

	n0 := deriveNonce(master, 0)
	if len(n0) != 12 {
		t.Fatalf("expected 12-byte nonce, got %d", len(n0))
	}
	if string(n0) != string(master) {
		t.Fatalf("nonce for idx 0 should equal master, got %x vs %x", n0, master)
	}

	n1 := deriveNonce(master, 1)
	if string(n1) == string(n0) {
		t.Fatal("nonce for idx 1 should differ from idx 0")
	}

	// uint32 max should not panic
	nMax := deriveNonce(master, 0xffffffff)
	if len(nMax) != 12 {
		t.Fatalf("expected 12-byte nonce for uint32 max")
	}
}

func TestReadChunkImmediateTerminator(t *testing.T) {
	gcm, err := cipher.NewGCM(blockCipher)
	if err != nil {
		t.Fatal(err)
	}
	masterNonce := make([]byte, 12)

	var term [chunkLenSize]byte
	binary.BigEndian.PutUint32(term[:], chunkTerm)

	pt, err := readChunk(bytes.NewReader(term[:]), gcm, masterNonce, 0)
	if err != nil {
		t.Fatalf("readChunk terminator: %v", err)
	}
	if pt != nil {
		t.Fatal("expected nil for terminator chunk")
	}
}

var blockCipher = func() cipher.Block {
	c, _ := aes.NewCipher(make([]byte, 32))
	return c
}()

func TestExactChunkBoundary(t *testing.T) {
	password := []byte("chunkboundary")
	data := make([]byte, chunkSize) // exactly 64 KiB
	for i := range data {
		data[i] = byte(i % 251)
	}

	cipherdata, err := Encrypt(password, data, "aes", "bin")
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	plaintext, _, err := Decrypt(password, cipherdata)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	if !bytes.Equal(plaintext, data) {
		t.Fatal("exact chunk boundary plaintext mismatch")
	}
}

func TestAESDecryptV1Truncated(t *testing.T) {
	_, _, err := aesDecryptV1([]byte("pw"), []byte("short"))
	if err == nil {
		t.Fatal("expected error for truncated v1 data")
	}
}

func TestChaChaDecryptV1Truncated(t *testing.T) {
	_, _, err := chachaDecryptV1([]byte("pw"), []byte("short"))
	if err == nil {
		t.Fatal("expected error for truncated v1 data")
	}
}

func TestDecryptGarbageData(t *testing.T) {
	tests := []string{
		"",
		"not-a-valid-format",
		string(make([]byte, 100)), // random binary
	}
	for _, tc := range tests {
		t.Run("", func(t *testing.T) {
			_, _, err := Decrypt([]byte("pw"), []byte(tc))
			if err == nil {
				t.Fatal("expected error for garbage data")
			}
		})
	}
}

func TestEncryptToPublicKeyEmptyData(t *testing.T) {
	id, err := GenerateIdentity("")
	if err != nil {
		t.Fatal(err)
	}

	recip, _ := NewX25519Recipient(id.Public)
	cipherdata, err := EncryptToPublicKey(recip, []byte{}, "")
	if err != nil {
		t.Fatalf("EncryptToPublicKey empty data failed: %v", err)
	}

	plaintext, _, err := DecryptWithIdentity(id, cipherdata)
	if err != nil {
		t.Fatalf("DecryptWithIdentity empty data failed: %v", err)
	}
	if len(plaintext) != 0 {
		t.Fatalf("expected empty result, got %d bytes", len(plaintext))
	}
}

func TestStreamEncryptEmptyReader(t *testing.T) {
	password := []byte("emptystream")

	var buf bytes.Buffer
	written, err := StreamEncrypt(password, bytes.NewReader([]byte{}), &buf, "aes", "")
	if err != nil {
		t.Fatalf("StreamEncrypt empty failed: %v", err)
	}
	if written != 0 {
		t.Fatalf("expected 0 bytes written, got %d", written)
	}

	var result bytes.Buffer
	_, err = StreamDecrypt(password, bytes.NewReader(buf.Bytes()), &result)
	if err != nil {
		t.Fatalf("StreamDecrypt empty failed: %v", err)
	}
	if result.Len() != 0 {
		t.Fatalf("expected empty result, got %d bytes", result.Len())
	}
}

func TestStreamDecryptV2UnsupportedAlgo(t *testing.T) {
	password := []byte("pw")
	data := []byte("plaintext")

	var buf bytes.Buffer
	_, err := StreamEncrypt(password, bytes.NewReader(data), &buf, "aes", "")
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the algo byte in the header.
	encrypted := buf.Bytes()
	encrypted[magicLen+1] = 0xff // invalid algo

	_, err = StreamDecrypt(password, bytes.NewReader(encrypted), &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected error for unsupported algo")
	}
}

func TestInspectV1Data(t *testing.T) {
	_, _, err := Inspect([]byte("not-cphx"))
	if err == nil {
		t.Fatal("expected error for non-v2 data")
	}
}

func TestMarshalIdentityEmptyLabel(t *testing.T) {
	id, err := GenerateIdentity("")
	if err != nil {
		t.Fatal(err)
	}

	data := MarshalIdentity(id)
	if !bytes.HasPrefix(data, []byte(identityLabel+"\n")) {
		t.Fatalf("expected label prefix")
	}
	// With empty label, no "# comment" line should appear.
	if bytes.Contains(data, []byte("# \n")) {
		t.Fatal("unexpected empty comment line")
	}
}

func TestUnmarshalIdentityWhitespace(t *testing.T) {
	id, err := GenerateIdentity("test")
	if err != nil {
		t.Fatal(err)
	}
	marshaled := MarshalIdentity(id)

	// Add blank lines and trailing whitespace.
	relaxed := append([]byte("\n  \n"), marshaled...)
	relaxed = append(relaxed, []byte("\n  \n")...)

	id2, err := UnmarshalIdentity(relaxed)
	if err != nil {
		t.Fatalf("UnmarshalIdentity with whitespace failed: %v", err)
	}
	if !bytes.Equal(id.Seed, id2.Seed) {
		t.Fatal("seed mismatch after whitespace-tolerant unmarshal")
	}
}

func TestEncryptToPublicKeyEmptyRecipientPub(t *testing.T) {
	_, err := NewX25519Recipient([]byte{})
	if err == nil {
		t.Fatal("expected error for empty recipient public key")
	}
	_, err = NewX25519Recipient([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for short recipient public key")
	}
}

func TestEmptyDataEncryptDecrypt(t *testing.T) {
	password := []byte("password")
	data := []byte{}

	cipherdata, err := Encrypt(password, data, "aes", "")
	if err != nil {
		t.Fatalf("empty encrypt failed: %v", err)
	}

	result, _, err := Decrypt(password, cipherdata)
	if err != nil {
		t.Fatalf("empty decrypt failed: %v", err)
	}
	if len(result) != 0 {
		t.Fatalf("expected empty result, got %d bytes", len(result))
	}
}

// -- SSH key support tests --

func TestEd25519SeedToX25519(t *testing.T) {
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = byte(i)
	}
	scalar := ed25519SeedToX25519(seed)
	if len(scalar) != 32 {
		t.Fatalf("expected 32 bytes, got %d", len(scalar))
	}
	// Check clamping
	if scalar[0]&7 != 0 {
		t.Fatal("lower 3 bits of byte 0 should be cleared")
	}
	if scalar[31]&128 != 0 {
		t.Fatal("bit 7 of byte 31 should be set")
	}
	if scalar[31]&64 == 0 {
		t.Fatal("bit 6 of byte 31 should be set")
	}
}

func TestEd25519SeedToX25519Determinism(t *testing.T) {
	seed := []byte("01234567890123456789012345678901") // 32 bytes
	s1 := ed25519SeedToX25519(seed)
	s2 := ed25519SeedToX25519(seed)
	if !bytes.Equal(s1, s2) {
		t.Fatal("expected deterministic derivation")
	}
}

func generateTestEd25519Key(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey, string, []byte) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Marshal public key as SSH authorized key
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	pubLine := string(ssh.MarshalAuthorizedKey(sshPub))

	// Marshal private key as OpenSSH PEM
	privBlock, err := ssh.MarshalPrivateKey(priv, "test")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	privPEM := pem.EncodeToMemory(privBlock)

	return pub, priv, pubLine, privPEM
}

func TestParseSSHIdentity(t *testing.T) {
	_, _, _, privPEM := generateTestEd25519Key(t)

	id, err := ParseSSHIdentity(privPEM)
	if err != nil {
		t.Fatalf("ParseSSHIdentity: %v", err)
	}
	if id == nil {
		t.Fatal("expected non-nil identity")
	}
	if id.KeyType() != KeyTypeX25519 {
		t.Fatalf("expected X25519 key type, got %v", id.KeyType())
	}
	if len(id.PrivateBytes()) != 32 {
		t.Fatalf("expected 32-byte seed, got %d", len(id.PrivateBytes()))
	}
	if len(id.PublicBytes()) != 32 {
		t.Fatalf("expected 32-byte public key, got %d", len(id.PublicBytes()))
	}
}

func TestParseSSHRecipient(t *testing.T) {
	_, _, pubLine, _ := generateTestEd25519Key(t)

	pubKey, err := ParseSSHRecipient(strings.TrimSpace(pubLine))
	if err != nil {
		t.Fatalf("ParseSSHRecipient: %v", err)
	}
	if pubKey.KeyType() != KeyTypeX25519 {
		t.Fatalf("expected X25519 key type, got %v", pubKey.KeyType())
	}
	if len(pubKey.PublicBytes()) != 32 {
		t.Fatalf("expected 32-byte public key, got %d", len(pubKey.PublicBytes()))
	}
}

func TestSSHRoundtrip(t *testing.T) {
	_, _, pubLine, privPEM := generateTestEd25519Key(t)

	parsedPub, err := ParseSSHRecipient(strings.TrimSpace(pubLine))
	if err != nil {
		t.Fatalf("ParseSSHRecipient: %v", err)
	}

	id, err := ParseSSHIdentity(privPEM)
	if err != nil {
		t.Fatalf("ParseSSHIdentity: %v", err)
	}

	plaintext := []byte("ssh roundtrip test data")
	encrypted, err := EncryptToPublicKey(parsedPub, plaintext, "txt")
	if err != nil {
		t.Fatalf("EncryptToPublicKey: %v", err)
	}

	decrypted, ext, err := DecryptWithIdentity(id, encrypted)
	if err != nil {
		t.Fatalf("DecryptWithIdentity: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("data mismatch: got %q, want %q", string(decrypted), string(plaintext))
	}
	if ext != "txt" {
		t.Fatalf("extension mismatch: got %q, want %q", ext, "txt")
	}
}

func TestParseSSHIdentityRSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	privBlock, err := ssh.MarshalPrivateKey(rsaKey, "test-rsa")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	privPEM := pem.EncodeToMemory(privBlock)

	id, err := ParseSSHIdentity(privPEM)
	if err != nil {
		t.Fatalf("ParseSSHIdentity RSA: %v", err)
	}
	if id.KeyType() != KeyTypeRSA {
		t.Fatalf("expected RSA key type, got %v", id.KeyType())
	}
	if len(id.PublicBytes()) == 0 {
		t.Fatal("expected non-empty public key")
	}
}

func TestRSARoundtrip(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	privBlock, err := ssh.MarshalPrivateKey(rsaKey, "test-rsa")
	if err != nil {
		t.Fatalf("MarshalPrivateKey: %v", err)
	}
	privPEM := pem.EncodeToMemory(privBlock)

	pubBlock, err := ssh.NewPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	pubLine := string(ssh.MarshalAuthorizedKey(pubBlock))

	priv, err := ParseSSHIdentity(privPEM)
	if err != nil {
		t.Fatalf("ParseSSHIdentity: %v", err)
	}
	pub, err := ParseSSHRecipient(strings.TrimSpace(pubLine))
	if err != nil {
		t.Fatalf("ParseSSHRecipient: %v", err)
	}

	plaintext := []byte("rsa roundtrip test data")
	encrypted, err := EncryptToPublicKey(pub, plaintext, "txt")
	if err != nil {
		t.Fatalf("EncryptToPublicKey: %v", err)
	}

	decrypted, ext, err := DecryptWithIdentity(priv, encrypted)
	if err != nil {
		t.Fatalf("DecryptWithIdentity: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("data mismatch: got %q, want %q", string(decrypted), string(plaintext))
	}
	if ext != "txt" {
		t.Fatalf("extension mismatch: got %q, want %q", ext, "txt")
	}
}

func TestRSAMultiRoundtrip(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)

	priv1 := &rsaIdentity{priv: key1}
	priv2 := &rsaIdentity{priv: key2}
	pub1 := &rsaRecipient{pub: &key1.PublicKey}
	pub2 := &rsaRecipient{pub: &key2.PublicKey}

	plaintext := []byte("rsa multi-recipient test")
	encrypted, err := EncryptToPublicKeys([]Recipient{pub1, pub2}, plaintext, "multi")
	if err != nil {
		t.Fatalf("EncryptToPublicKeys RSA multi: %v", err)
	}

	for i, priv := range []PrivateKey{priv1, priv2} {
		decrypted, ext, err := DecryptWithIdentity(priv, encrypted)
		if err != nil {
			t.Fatalf("DecryptWithIdentity recipient %d: %v", i+1, err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("recipient %d plaintext mismatch", i+1)
		}
		if ext != "multi" {
			t.Fatalf("recipient %d ext mismatch: got %q, want %q", i+1, ext, "multi")
		}
	}
}

func TestHybridRoundtrip(t *testing.T) {
	xID, _ := GenerateIdentity("")
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	xPub, _ := NewX25519Recipient(xID.Public)
	rPub := &rsaRecipient{pub: &rsaKey.PublicKey}
	rPriv := &rsaIdentity{priv: rsaKey}

	plaintext := []byte("hybrid rsa+x25519 test")
	encrypted, err := EncryptToPublicKeys([]Recipient{xPub, rPub}, plaintext, "hyb")
	if err != nil {
		t.Fatalf("EncryptToPublicKeys hybrid: %v", err)
	}

	for i, id := range []PrivateKey{xID, rPriv} {
		decrypted, ext, err := DecryptWithIdentity(id, encrypted)
		if err != nil {
			t.Fatalf("DecryptWithIdentity hybrid recipient %d: %v", i+1, err)
		}
		if !bytes.Equal(decrypted, plaintext) {
			t.Fatalf("hybrid recipient %d plaintext mismatch", i+1)
		}
		if ext != "hyb" {
			t.Fatalf("hybrid recipient %d ext mismatch: got %q, want %q", i+1, ext, "hyb")
		}
	}
}

func TestParseSSHIdentityInvalid(t *testing.T) {
	_, err := ParseSSHIdentity([]byte("not a valid SSH key"))
	if err == nil {
		t.Fatal("expected error for invalid data")
	}
}

func TestParseSSHRecipientInvalid(t *testing.T) {
	_, err := ParseSSHRecipient("not-a-valid-ssh-key")
	if err == nil {
		t.Fatal("expected error for invalid recipient")
	}
}

func TestParseSSHRecipientGoEncFormat(t *testing.T) {
	// cphx... recipients should NOT be parsed by ParseSSHRecipient
	_, err := ParseSSHRecipient("cphxdeadbeef")
	if err == nil {
		t.Fatal("expected error for cphx recipient")
	}
}

func TestIsSSHPrivateKey(t *testing.T) {
	_, _, _, privPEM := generateTestEd25519Key(t)
	if !IsSSHPrivateKey(privPEM) {
		t.Fatal("expected true for valid SSH private key")
	}
	if IsSSHPrivateKey([]byte("not a key")) {
		t.Fatal("expected false for non-key data")
	}
	if IsSSHPrivateKey([]byte("-----BEGIN CERTIFICATE-----\nfoo\n-----END CERTIFICATE-----")) {
		t.Fatal("expected false for certificate PEM")
	}
}

func TestIsSSHPublicKey(t *testing.T) {
	_, _, pubLine, _ := generateTestEd25519Key(t)
	if !IsSSHPublicKey(strings.TrimSpace(pubLine)) {
		t.Fatal("expected true for valid SSH public key")
	}
	if IsSSHPublicKey("not a public key") {
		t.Fatal("expected false for non-key string")
	}
}

func TestSSHKeyMultiRecipient(t *testing.T) {
	_, _, pubLine1, privPEM1 := generateTestEd25519Key(t)
	_, _, pubLine2, _ := generateTestEd25519Key(t)

	pub1, _ := ParseSSHRecipient(strings.TrimSpace(pubLine1))
	pub2, _ := ParseSSHRecipient(strings.TrimSpace(pubLine2))
	id1, _ := ParseSSHIdentity(privPEM1)

	plaintext := []byte("multi-ssh test")
	encrypted, err := EncryptToPublicKeys([]Recipient{pub1, pub2}, plaintext, "txt")
	if err != nil {
		t.Fatalf("EncryptToPublicKeys: %v", err)
	}

	// id1 should be able to decrypt
	decrypted, _, err := DecryptWithIdentity(id1, encrypted)
	if err != nil {
		t.Fatalf("DecryptWithIdentity: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("data mismatch: got %q, want %q", string(decrypted), string(plaintext))
	}
}

func TestEd25519PubToX25519Invalid(t *testing.T) {
	_, err := ed25519PubToX25519([]byte{1, 2, 3})
	if err == nil {
		t.Fatal("expected error for invalid point")
	}
}

func TestSSHIdentityPubMatchesRecipient(t *testing.T) {
	_, _, pubLine, privPEM := generateTestEd25519Key(t)

	parsedPub, _ := ParseSSHRecipient(strings.TrimSpace(pubLine))
	id, _ := ParseSSHIdentity(privPEM)

	if !bytes.Equal(parsedPub.PublicBytes(), id.PublicBytes()) {
		t.Fatalf("public key mismatch:\n  recipient: %x\n  identity:  %x", parsedPub.PublicBytes(), id.PublicBytes())
	}
}

func TestInspectFileInfoAES(t *testing.T) {
	password := []byte("testpassword")
	data := []byte("hello world")
	ext := "txt"

	encrypted, err := Encrypt(password, data, "aes", ext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	fi, err := InspectFileInfo(encrypted)
	if err != nil {
		t.Fatalf("InspectFileInfo: %v", err)
	}

	if fi.Algorithm != "aes" {
		t.Errorf("want algorithm 'aes', got %q", fi.Algorithm)
	}
	if fi.KDF != "scrypt" {
		t.Errorf("want KDF 'scrypt', got %q", fi.KDF)
	}
	if fi.Extension != ext {
		t.Errorf("want extension %q, got %q", ext, fi.Extension)
	}
	if fi.FormatVersion != 1 {
		t.Errorf("want FormatVersion 1, got %d", fi.FormatVersion)
	}
	if fi.NumRecipients != 0 {
		t.Errorf("want NumRecipients 0 for password-based, got %d", fi.NumRecipients)
	}
	if len(fi.RecipientIDs) != 0 {
		t.Errorf("want empty RecipientIDs, got %v", fi.RecipientIDs)
	}
}

func TestInspectFileInfoChaCha(t *testing.T) {
	password := []byte("testpassword")
	data := []byte("hello chacha")
	ext := "dat"

	encrypted, err := Encrypt(password, data, "chacha20", ext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	fi, err := InspectFileInfo(encrypted)
	if err != nil {
		t.Fatalf("InspectFileInfo: %v", err)
	}

	if fi.Algorithm != "chacha20" {
		t.Errorf("want algorithm 'chacha20', got %q", fi.Algorithm)
	}
	if fi.KDF != "argon2id" {
		t.Errorf("want KDF 'argon2id', got %q", fi.KDF)
	}
	if fi.Extension != ext {
		t.Errorf("want extension %q, got %q", ext, fi.Extension)
	}
}

func TestInspectFileInfoPubKeySingle(t *testing.T) {
	id, err := GenerateIdentity("test")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	data := []byte("hello pubkey")
	ext := "secret"

	recip, _ := NewX25519Recipient(id.Public)
	encrypted, err := EncryptToPublicKey(recip, data, ext)
	if err != nil {
		t.Fatalf("EncryptToPublicKey: %v", err)
	}

	fi, err := InspectFileInfo(encrypted)
	if err != nil {
		t.Fatalf("InspectFileInfo: %v", err)
	}

	if fi.Algorithm != "pubkey" {
		t.Errorf("want algorithm 'pubkey', got %q", fi.Algorithm)
	}
	if fi.KDF != "hkdf-sha256" {
		t.Errorf("want KDF 'hkdf-sha256', got %q", fi.KDF)
	}
	if fi.Extension != ext {
		t.Errorf("want extension %q, got %q", ext, fi.Extension)
	}
	if fi.NumRecipients != 1 {
		t.Errorf("want NumRecipients 1, got %d", fi.NumRecipients)
	}
	if len(fi.RecipientIDs) != 0 {
		t.Errorf("want empty RecipientIDs for single-recipient, got %v", fi.RecipientIDs)
	}
}

func TestInspectFileInfoPubKeyMulti(t *testing.T) {
	id1, err := GenerateIdentity("alice")
	if err != nil {
		t.Fatalf("GenerateIdentity id1: %v", err)
	}
	id2, err := GenerateIdentity("bob")
	if err != nil {
		t.Fatalf("GenerateIdentity id2: %v", err)
	}
	id3, err := GenerateIdentity("carol")
	if err != nil {
		t.Fatalf("GenerateIdentity id3: %v", err)
	}
	data := []byte("hello multi")
	ext := "shared"

	recip1, _ := NewX25519Recipient(id1.Public)
	recip2, _ := NewX25519Recipient(id2.Public)
	recip3, _ := NewX25519Recipient(id3.Public)
	encrypted, err := EncryptToPublicKeys([]Recipient{recip1, recip2, recip3}, data, ext)
	if err != nil {
		t.Fatalf("EncryptToPublicKeys: %v", err)
	}

	fi, err := InspectFileInfo(encrypted)
	if err != nil {
		t.Fatalf("InspectFileInfo: %v", err)
	}

	if fi.Algorithm != "pubkey-multi" {
		t.Errorf("want algorithm 'pubkey-multi', got %q", fi.Algorithm)
	}
	if fi.KDF != "hkdf-sha256" {
		t.Errorf("want KDF 'hkdf-sha256', got %q", fi.KDF)
	}
	if fi.Extension != ext {
		t.Errorf("want extension %q, got %q", ext, fi.Extension)
	}
	if fi.NumRecipients != 3 {
		t.Errorf("want NumRecipients 3, got %d", fi.NumRecipients)
	}
	if len(fi.RecipientIDs) != 3 {
		t.Fatalf("want 3 RecipientIDs, got %d", len(fi.RecipientIDs))
	}
	// Each ID should be a 16-char hex string.
	for i, id := range fi.RecipientIDs {
		if len(id) != 16 {
			t.Errorf("recipient %d ID length is %d, want 16", i+1, len(id))
		}
	}
}

func TestInspectFileInfoUnknownFormat(t *testing.T) {
	_, err := InspectFileInfo([]byte("not encrypted data"))
	if err != ErrUnknownFormat {
		t.Fatalf("want ErrUnknownFormat, got %v", err)
	}
}

func TestInspectFileInfoTezExtension(t *testing.T) {
	password := []byte("testpassword")
	data := []byte("tar data")
	ext := "tez"

	encrypted, err := Encrypt(password, data, "aes", ext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	fi, err := InspectFileInfo(encrypted)
	if err != nil {
		t.Fatalf("InspectFileInfo: %v", err)
	}

	if fi.Extension != "tez" {
		t.Errorf("want extension 'tez', got %q", fi.Extension)
	}
}

func TestInspectFileInfoRSASingle(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	data := []byte("hello rsa single")
	ext := "rsa"

	encrypted, err := rsaSingleEncrypt(&key.PublicKey, data, ext)
	if err != nil {
		t.Fatalf("rsaSingleEncrypt: %v", err)
	}

	fi, err := InspectFileInfo(encrypted)
	if err != nil {
		t.Fatalf("InspectFileInfo: %v", err)
	}

	if fi.Algorithm != "pubkey-rsa" {
		t.Errorf("want algorithm 'pubkey-rsa', got %q", fi.Algorithm)
	}
	if fi.KDF != "rsa-oaep" {
		t.Errorf("want KDF 'rsa-oaep', got %q", fi.KDF)
	}
	if fi.Extension != ext {
		t.Errorf("want extension %q, got %q", ext, fi.Extension)
	}
	if fi.NumRecipients != 1 {
		t.Errorf("want NumRecipients 1, got %d", fi.NumRecipients)
	}
	if len(fi.RecipientIDs) != 1 {
		t.Fatalf("want 1 RecipientID, got %d", len(fi.RecipientIDs))
	}
	if len(fi.RecipientIDs[0]) != 16 {
		t.Errorf("want RecipientID 16 hex chars, got %d", len(fi.RecipientIDs[0]))
	}
}

func TestInspectFileInfoRSAMulti(t *testing.T) {
	key1, _ := rsa.GenerateKey(rand.Reader, 2048)
	key2, _ := rsa.GenerateKey(rand.Reader, 2048)
	data := []byte("hello rsa multi")
	ext := "rmulti"

	encrypted, err := rsaMultiEncrypt([]*rsa.PublicKey{&key1.PublicKey, &key2.PublicKey}, data, ext)
	if err != nil {
		t.Fatalf("rsaMultiEncrypt: %v", err)
	}

	fi, err := InspectFileInfo(encrypted)
	if err != nil {
		t.Fatalf("InspectFileInfo: %v", err)
	}

	if fi.Algorithm != "pubkey-rsa-multi" {
		t.Errorf("want algorithm 'pubkey-rsa-multi', got %q", fi.Algorithm)
	}
	if fi.KDF != "rsa-oaep" {
		t.Errorf("want KDF 'rsa-oaep', got %q", fi.KDF)
	}
	if fi.Extension != ext {
		t.Errorf("want extension %q, got %q", ext, fi.Extension)
	}
	if fi.NumRecipients != 2 {
		t.Errorf("want NumRecipients 2, got %d", fi.NumRecipients)
	}
	if len(fi.RecipientIDs) != 2 {
		t.Fatalf("want 2 RecipientIDs, got %d", len(fi.RecipientIDs))
	}
	for i, id := range fi.RecipientIDs {
		if len(id) != 16 {
			t.Errorf("recipient %d ID length is %d, want 16", i+1, len(id))
		}
	}
}

// TestDecryptOldMagicBackwardCompat verifies that data encrypted with the
// old "goenc" magic header can still be decrypted by the current code.
func TestDecryptOldMagicBackwardCompat(t *testing.T) {
	password := []byte("backward-compat-password")
	plaintext := []byte("old format data for backward compat test")
	ext := "txt"

	// Encrypt with new format, then patch magic to old format.
	ct, err := Encrypt(password, plaintext, "aes", ext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	oldCT := make([]byte, len(ct)+1)
	copy(oldCT[:5], "goenc")
	copy(oldCT[5:], ct[magicLen:])

	// Verify isV2Format recognizes old magic.
	if !isV2Format(oldCT) {
		t.Fatal("isV2Format should detect old magic")
	}

	// Verify parseHeader parses old-format header.
	hdr, hdrLen, err := parseHeader(oldCT)
	if err != nil {
		t.Fatalf("parseHeader with old magic: %v", err)
	}
	if hdr.algo != algoAES {
		t.Fatalf("expected algo AES (%d), got %d", algoAES, hdr.algo)
	}
	if hdr.ext != ext {
		t.Fatalf("expected ext %q, got %q", ext, hdr.ext)
	}
	if hdrLen < 9 {
		t.Fatalf("header length too small for old format: %d", hdrLen)
	}

	// Decrypt with old-format data.
	decrypted, gotExt, err := Decrypt(password, oldCT)
	if err != nil {
		t.Fatalf("Decrypt with old magic: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("Decrypt data mismatch: got %q, want %q", string(decrypted), string(plaintext))
	}
	if gotExt != ext {
		t.Fatalf("Decrypt ext mismatch: got %q, want %q", gotExt, ext)
	}

	// Also test StreamDecrypt with old magic.
	var buf bytes.Buffer
	streamExt, err := StreamDecrypt(password, bytes.NewReader(oldCT), &buf)
	if err != nil {
		t.Fatalf("StreamDecrypt with old magic: %v", err)
	}
	if streamExt != ext {
		t.Fatalf("StreamDecrypt ext mismatch: got %q, want %q", streamExt, ext)
	}
	if !bytes.Equal(buf.Bytes(), plaintext) {
		t.Fatalf("StreamDecrypt data mismatch: got %q, want %q", string(buf.Bytes()), string(plaintext))
	}
}

// TestDecryptOldMagicChaCha verifies old-magic backward compat with ChaCha20.
func TestDecryptOldMagicChaCha(t *testing.T) {
	password := []byte("chacha-old-magic")
	plaintext := []byte("chacha20 old format data")
	ext := "dat"

	ct, err := Encrypt(password, plaintext, "chacha20", ext)
	if err != nil {
		t.Fatalf("Encrypt ChaCha20: %v", err)
	}
	oldCT := make([]byte, len(ct)+1)
	copy(oldCT[:5], "goenc")
	copy(oldCT[5:], ct[magicLen:])

	decrypted, gotExt, err := Decrypt(password, oldCT)
	if err != nil {
		t.Fatalf("Decrypt old-magic ChaCha20: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("data mismatch: got %q, want %q", string(decrypted), string(plaintext))
	}
	if gotExt != ext {
		t.Fatalf("ext mismatch: got %q, want %q", gotExt, ext)
	}
}

// TestDecryptOldMagicPubKey verifies old-magic backward compat with pubkey encryption.
func TestDecryptOldMagicPubKey(t *testing.T) {
	id, err := GenerateIdentity("old-magic-test")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	plaintext := []byte("pubkey old format data")
	ext := "secret"

	recip, _ := NewX25519Recipient(id.Public)
	ct, err := EncryptToPublicKey(recip, plaintext, ext)
	if err != nil {
		t.Fatalf("EncryptToPublicKey: %v", err)
	}
	oldCT := make([]byte, len(ct)+1)
	copy(oldCT[:5], "goenc")
	copy(oldCT[5:], ct[magicLen:])

	decrypted, gotExt, err := DecryptWithIdentity(id, oldCT)
	if err != nil {
		t.Fatalf("DecryptWithIdentity old magic: %v", err)
	}
	if !bytes.Equal(decrypted, plaintext) {
		t.Fatalf("data mismatch: got %q, want %q", string(decrypted), string(plaintext))
	}
	if gotExt != ext {
		t.Fatalf("ext mismatch: got %q, want %q", gotExt, ext)
	}
}

func TestInspectFileInfoHybrid(t *testing.T) {
	xID, err := GenerateIdentity("x25519")
	if err != nil {
		t.Fatalf("GenerateIdentity: %v", err)
	}
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	data := []byte("hello hybrid")
	ext := "hyb"

	xPub, _ := NewX25519Recipient(xID.Public)
	rPub := &rsaRecipient{pub: &rsaKey.PublicKey}

	encrypted, err := EncryptToPublicKeys([]Recipient{xPub, rPub}, data, ext)
	if err != nil {
		t.Fatalf("EncryptToPublicKeys hybrid: %v", err)
	}

	fi, err := InspectFileInfo(encrypted)
	if err != nil {
		t.Fatalf("InspectFileInfo: %v", err)
	}

	if fi.Algorithm != "pubkey-hybrid" {
		t.Errorf("want algorithm 'pubkey-hybrid', got %q", fi.Algorithm)
	}
	if fi.KDF != "rsa-oaep" {
		t.Errorf("want KDF 'rsa-oaep', got %q", fi.KDF)
	}
	if fi.Extension != ext {
		t.Errorf("want extension %q, got %q", ext, fi.Extension)
	}
	if fi.NumRecipients != 2 {
		t.Errorf("want NumRecipients 2, got %d", fi.NumRecipients)
	}
	if len(fi.RecipientIDs) != 2 {
		t.Fatalf("want 2 RecipientIDs, got %d", len(fi.RecipientIDs))
	}
	for i, id := range fi.RecipientIDs {
		if len(id) != 16 {
			t.Errorf("recipient %d ID length is %d, want 16", i+1, len(id))
		}
	}
}
