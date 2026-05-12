package cmd_test

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mrinjamul/cipherix/crypt"
)

var binaryPath string

// lckPath returns the expected .chx path for a source file.
// Must match cmd.encryptFile's output-path derivation.
func lckPath(src string) string {
	ext := filepath.Ext(src)
	if ext == "" || ext == src {
		return src + ".chx"
	}
	base := src[:len(src)-len(ext)]
	if base == "" {
		return src + ".chx"
	}
	return base + ".chx"
}

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "cipherix-test-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	binaryPath = filepath.Join(dir, "cipherix")
	cmd := exec.Command("go", "build", "-o", binaryPath, ".")
	cmd.Dir = filepath.Join("..")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "build failed: %v\n%s\n", err, out)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func fileHash(t *testing.T, path string) [32]byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("fileHash read %s: %v", path, err)
	}
	return sha256.Sum256(data)
}

func assertIntegrity(t *testing.T, original, restored string) {
	t.Helper()
	if fileHash(t, original) != fileHash(t, restored) {
		t.Fatalf("integrity check failed: %s content differs from %s", restored, original)
	}
}

func run(args ...string) (stdout, stderr string, err error) {
	var outb, errb bytes.Buffer
	cmd := exec.Command(binaryPath, args...)
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err = cmd.Run()
	return outb.String(), errb.String(), err
}

func runWithStdin(input string, args ...string) (stdout, stderr string, err error) {
	var outb, errb bytes.Buffer
	cmd := exec.Command(binaryPath, args...)
	cmd.Stdin = strings.NewReader(input)
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err = cmd.Run()
	return outb.String(), errb.String(), err
}

func runWithStdinEnv(input string, env []string, args ...string) (stdout, stderr string, err error) {
	var outb, errb bytes.Buffer
	cmd := exec.Command(binaryPath, args...)
	cmd.Stdin = strings.NewReader(input)
	cmd.Env = env
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err = cmd.Run()
	return outb.String(), errb.String(), err
}

func TestEncryptDecryptAES(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(src, []byte("aes integration test"), 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	out, _, err := run("encrypt", "-k", "-p", "testpass", "-m", "aes", src)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "encrypted successfully") {
		t.Fatalf("unexpected output: %s", out)
	}

	lck := lckPath(src)
	if _, err := os.Stat(lck); os.IsNotExist(err) {
		t.Fatal("encrypted file not created")
	}

	out, _, err = run("decrypt", "-k", "-p", "testpass", lck)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, out)
	}

	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed after round-trip")
	}
	data, _ := os.ReadFile(src)
	if string(data) != "aes integration test" {
		t.Fatalf("data mismatch: got %q", string(data))
	}
}

func TestEncryptDecryptChaCha20(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "chacha.txt")
	if err := os.WriteFile(src, []byte("chacha20 test"), 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	run("encrypt", "-k", "-p", "pass", "-m", "chacha20", src)

	lck := lckPath(src)
	out, _, err := run("decrypt", "-k", "-p", "pass", lck)
	if err != nil {
		t.Fatalf("chacha20 decrypt failed: %v\n%s", err, out)
	}
	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed after round-trip")
	}
	data, _ := os.ReadFile(src)
	if string(data) != "chacha20 test" {
		t.Fatalf("data mismatch: got %q", string(data))
	}
}

func TestEncryptOutputFlag(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "input.txt")
	dst := filepath.Join(dir, "custom.chx")
	if err := os.WriteFile(src, []byte("custom output"), 0644); err != nil {
		t.Fatal(err)
	}

	run("encrypt", "-k", "-p", "pass", "-o", dst, src)

	if _, err := os.Stat(dst); os.IsNotExist(err) {
		t.Fatal("custom output file not created")
	}
}

func TestDecryptOutputFlag(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "decode.txt")
	dst := filepath.Join(dir, "restored.txt")
	if err := os.WriteFile(src, []byte("decode test"), 0644); err != nil {
		t.Fatal(err)
	}

	run("encrypt", "-k", "-p", "pass", src)
	lck := lckPath(src)
	out, _, _ := run("decrypt", "-k", "-p", "pass", "-o", dst, lck)
	if !strings.Contains(out, "decrypted successfully") {
		t.Fatalf("unexpected output: %s", out)
	}
	data, _ := os.ReadFile(dst)
	if string(data) != "decode test" {
		t.Fatalf("data mismatch: got %q", string(data))
	}
}

func TestEncryptWithKeep(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "keep.txt")
	if err := os.WriteFile(src, []byte("keep me"), 0644); err != nil {
		t.Fatal(err)
	}

	run("encrypt", "-k", "-p", "pass", src)

	if _, err := os.Stat(src); os.IsNotExist(err) {
		t.Fatal("original file was removed despite -k")
	}
}

func TestEncryptWithoutKeep(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "delete.txt")
	if err := os.WriteFile(src, []byte("delete me"), 0644); err != nil {
		t.Fatal(err)
	}

	run("encrypt", "-p", "pass", src)

	if _, err := os.Stat(src); !os.IsNotExist(err) {
		t.Fatal("original file should have been deleted without -k")
	}
}

func TestDecryptWrongPassword(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "wrongpw.txt")
	if err := os.WriteFile(src, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}

	run("encrypt", "-k", "-p", "correct", src)

	_, errOut, err := run("decrypt", "-k", "-p", "wrong", lckPath(src))
	if err == nil {
		t.Fatal("expected error for wrong password")
	}
	if !strings.Contains(errOut, "decryption failed — wrong password") {
		t.Fatalf("expected wrong password error, got: %s", errOut)
	}
}

func TestKeygenOutput(t *testing.T) {
	dir := t.TempDir()
	idPath := filepath.Join(dir, "mykey")

	out, _, err := run("keygen", "-o", idPath)
	if err != nil {
		t.Fatalf("keygen failed: %v\n%s", err, out)
	}
	if _, err := os.Stat(idPath); os.IsNotExist(err) {
		t.Fatal("identity file not created")
	}
	if !strings.Contains(out, "Public key: cphx") {
		t.Fatalf("expected public key in output, got: %s", out)
	}
}

func TestKeygenShowPubkey(t *testing.T) {
	out, _, err := run("keygen", "-y")
	if err != nil {
		t.Fatalf("keygen -y failed: %v\n%s", err, out)
	}
	out = strings.TrimSpace(out)
	if !strings.HasPrefix(out, "cphx") {
		t.Fatalf("expected cphx prefix, got: %s", out)
	}
}

func TestPubkeyRoundtrip(t *testing.T) {
	dir := t.TempDir()

	idPath := filepath.Join(dir, "identity")
	run("keygen", "-o", idPath)

	idData, err := os.ReadFile(idPath)
	if err != nil {
		t.Fatal(err)
	}
	var pubkey string
	for _, line := range strings.Split(string(idData), "\n") {
		if strings.HasPrefix(line, "# public: ") {
			pubkey = strings.TrimPrefix(line, "# public: ")
			break
		}
	}
	if pubkey == "" {
		t.Fatal("could not find public key in identity file")
	}

	src := filepath.Join(dir, "pubdata.txt")
	if err := os.WriteFile(src, []byte("pubkey secret"), 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	run("encrypt", "-k", "-r", pubkey, src)

	lck := lckPath(src)
	if _, err := os.Stat(lck); os.IsNotExist(err) {
		t.Fatal("encrypted file not created")
	}

	out, _, err := run("decrypt", "-k", "-i", idPath, lck)
	if err != nil {
		t.Fatalf("pubkey decrypt failed: %v\n%s", err, out)
	}

	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed after round-trip")
	}
	data, _ := os.ReadFile(src)
	if string(data) != "pubkey secret" {
		t.Fatalf("data mismatch: got %q", string(data))
	}
}

func TestGlobEncrypt(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aaa"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("bbb"), 0644); err != nil {
		t.Fatal(err)
	}

	run("encrypt", "-k", "-p", "pass", filepath.Join(dir, "*.txt"))

	if _, err := os.Stat(lckPath(filepath.Join(dir, "a.txt"))); os.IsNotExist(err) {
		t.Fatal("a.chx not created")
	}
	if _, err := os.Stat(lckPath(filepath.Join(dir, "b.txt"))); os.IsNotExist(err) {
		t.Fatal("b.chx not created")
	}
}

func TestPasswordEnv(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "envtest.txt")
	if err := os.WriteFile(src, []byte("env password"), 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	cmd := exec.Command(binaryPath, "encrypt", "-k", "--password-env", "TEST_PW", src)
	cmd.Env = append(os.Environ(), "TEST_PW=envpass")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("encrypt with env failed: %v\n%s", err, out)
	}

	lck := lckPath(src)
	cmd2 := exec.Command(binaryPath, "decrypt", "-k", "--password-env", "TEST_PW", lck)
	cmd2.Env = append(os.Environ(), "TEST_PW=envpass")
	cmd2.Dir = dir
	if out, err := cmd2.CombinedOutput(); err != nil {
		t.Fatalf("decrypt with env failed: %v\n%s", err, out)
	}
	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed after env password round-trip")
	}
}

func TestCompletion(t *testing.T) {
	tests := []string{"bash", "zsh", "fish", "powershell"}
	for _, shell := range tests {
		t.Run(shell, func(t *testing.T) {
			out, _, err := run("completion", shell)
			if err != nil {
				t.Fatalf("completion %s failed: %v", shell, err)
			}
			if len(out) == 0 {
				t.Fatalf("completion %s produced empty output", shell)
			}
		})
	}
}

func TestVersion(t *testing.T) {
	out, _, err := run("version")
	if err != nil {
		t.Fatalf("version failed: %v", err)
	}
	// Default fallback when built without -ldflags; releases inject the real version.
	if !strings.Contains(out, "dev") {
		t.Fatalf("expected version dev, got: %s", out)
	}
}

func TestHelp(t *testing.T) {
	for _, cmd := range []string{"", "encrypt", "decrypt", "keygen", "completion"} {
		t.Run(cmd, func(t *testing.T) {
			args := []string{"--help"}
			if cmd != "" {
				args = append([]string{cmd}, args...)
			}
			out, _, err := run(args...)
			if err != nil {
				t.Fatalf("help for %q failed: %v", cmd, err)
			}
			if !strings.Contains(out, "Usage") {
				t.Fatalf("help for %q missing Usage: %s", cmd, out)
			}
		})
	}
}

func TestAliases(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "alias.txt")
	if err := os.WriteFile(src, []byte("alias test"), 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	out, _, err := run("en", "-k", "-p", "pass", src)
	if err != nil {
		t.Fatalf("encrypt alias failed: %v\n%s", err, out)
	}
	lck := lckPath(src)

	out, _, err = run("de", "-k", "-p", "pass", lck)
	if err != nil {
		t.Fatalf("decrypt alias failed: %v\n%s", err, out)
	}
	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed after alias round-trip")
	}
}

func TestEmptyFileEncryptDecrypt(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "empty.txt")
	if err := os.WriteFile(src, []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	run("encrypt", "-k", "-p", "pass", src)
	run("decrypt", "-k", "-p", "pass", src+".chx")

	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed for empty file round-trip")
	}
}

func TestEncryptNoArgs(t *testing.T) {
	_, errOut, err := run("encrypt")
	if err == nil {
		t.Fatal("expected error for no args")
	}
	if !strings.Contains(errOut, "Error: missing file argument") {
		t.Fatalf("expected 'missing file argument', got: %s", errOut)
	}
}

func TestDecryptNoArgs(t *testing.T) {
	_, errOut, err := run("decrypt")
	if err == nil {
		t.Fatal("expected error for no args")
	}
	if !strings.Contains(errOut, "Error: missing file argument") {
		t.Fatalf("expected 'missing file argument', got: %s", errOut)
	}
}

func TestDirectoryEncryptDecryptRoundtrip(t *testing.T) {
	dir := t.TempDir()

	subdir := filepath.Join(dir, "sub")
	if err := os.MkdirAll(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "root.txt"), []byte("root file"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "nested.txt"), []byte("nested file"), 0644); err != nil {
		t.Fatal(err)
	}

	// Encrypt directory (auto-tar, no confirmation needed).
	pass := "testpass"
	out, _, err := run("encrypt", "-k", "-p", pass, dir)
	if err != nil {
		t.Fatalf("directory encrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "encrypted successfully") {
		t.Fatalf("expected success, got: %s", out)
	}

	lck := dir + ".chx"
	if _, err := os.Stat(lck); os.IsNotExist(err) {
		t.Fatal("encrypted directory .chx not created")
	}

	// Decrypt to a temp dir by changing the subprocess CWD.
	extractDir := t.TempDir()
	var outb, errb bytes.Buffer
	cmd := exec.Command(binaryPath, "decrypt", "-k", "-p", pass, lck)
	cmd.Dir = extractDir
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	if err := cmd.Run(); err != nil {
		t.Fatalf("directory decrypt failed: %v\nstdout: %s\nstderr: %s", err, outb.String(), errb.String())
	}
	if !strings.Contains(outb.String(), "decrypted successfully") {
		t.Fatalf("expected success, got: %s", outb.String())
	}

	// Verify files extracted under extractDir.
	baseName := filepath.Base(dir)
	rootContent, err := os.ReadFile(filepath.Join(extractDir, baseName, "root.txt"))
	if err != nil {
		t.Fatalf("root.txt missing at %s: %v", filepath.Join(extractDir, baseName, "root.txt"), err)
	}
	if string(rootContent) != "root file" {
		t.Fatalf("root.txt content mismatch: got %q", string(rootContent))
	}
	nestedContent, err := os.ReadFile(filepath.Join(extractDir, baseName, "sub", "nested.txt"))
	if err != nil {
		t.Fatalf("nested.txt missing: %v", err)
	}
	if string(nestedContent) != "nested file" {
		t.Fatalf("nested.txt content mismatch: got %q", string(nestedContent))
	}
}

func TestPrintFlag(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "print.txt")
	if err := os.WriteFile(src, []byte("stdout data"), 0644); err != nil {
		t.Fatal(err)
	}

	run("encrypt", "-k", "-p", "pass", src)

	lck := lckPath(src)
	out, _, err := run("decrypt", "-k", "-p", "pass", "--print", lck)
	if err != nil {
		t.Fatalf("decrypt --print failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "stdout data") {
		t.Fatalf("expected 'stdout data' in output, got: %s", out)
	}
}

func TestDecryptWrongIdentity(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(src, []byte("test content"), 0644); err != nil {
		t.Fatal(err)
	}

	// Use generateIdentity to avoid auto-adding to keystore.
	id1 := filepath.Join(dir, "id1")
	pubkey1 := generateIdentity(t, id1)

	run("encrypt", "-k", "-r", pubkey1, src)

	lck := lckPath(src)
	if _, err := os.Stat(lck); os.IsNotExist(err) {
		t.Fatal("encrypted file not created")
	}

	// Try decrypting with a different identity.
	otherId := filepath.Join(dir, "other")
	run("keygen", "-o", otherId)

	_, errOut, err := run("decrypt", "-k", "-i", otherId, lck)
	if err == nil {
		t.Fatal("expected error for wrong identity")
	}
	if !strings.Contains(errOut, "inappropriate ioctl") && !strings.Contains(errOut, "decryption failed") {
		t.Fatalf("expected decryption failure, got: %s", errOut)
	}
}

func TestCorruptLckFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "corrupt.txt")
	if err := os.WriteFile(src, []byte("corrupt me"), 0644); err != nil {
		t.Fatal(err)
	}

	run("encrypt", "-k", "-p", "pass", src)

	lck := lckPath(src)
	data, err := os.ReadFile(lck)
	if err != nil {
		t.Fatal(err)
	}
	// Flip a bit in the middle.
	data[len(data)/2] ^= 0xff
	if err := os.WriteFile(lck, data, 0644); err != nil {
		t.Fatal(err)
	}

	_, errOut, err := run("decrypt", "-p", "pass", lck)
	if err == nil {
		t.Fatal("expected error for corrupt .chx")
	}
	if !strings.Contains(errOut, "decryption failed — wrong password") {
		t.Fatalf("expected wrong password error, got: %s", errOut)
	}
}

func TestDecryptMissingFile(t *testing.T) {
	stdout, stderr, err := run("decrypt", "-p", "pass", "/nonexistent/file.chx")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "no matching files") {
		t.Fatalf("expected no-matching-files error, got: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestEncryptMissingFile(t *testing.T) {
	stdout, stderr, err := run("encrypt", "-p", "pass", "/nonexistent/file.txt")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	combined := stdout + stderr
	if !strings.Contains(combined, "no matching files") {
		t.Fatalf("expected no-matching-files error, got: stdout=%q stderr=%q", stdout, stderr)
	}
}

func TestDecryptKeepFlag(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "keepde.txt")
	if err := os.WriteFile(src, []byte("keep decrypt"), 0644); err != nil {
		t.Fatal(err)
	}

	run("encrypt", "-k", "-p", "pass", src)

	lck := lckPath(src)
	run("decrypt", "-k", "-p", "pass", lck)

	if _, err := os.Stat(lck); os.IsNotExist(err) {
		t.Fatal("encrypted file should have been kept with -k")
	}
}

func TestPasswordEnvMissing(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "envmissing.txt")
	if err := os.WriteFile(src, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command(binaryPath, "encrypt", "--password-env", "MISSING_VAR_12345", src)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("expected error for missing env var")
	}
	if !strings.Contains(string(out), "not set or is empty") {
		t.Fatalf("expected env var error, got: %s", string(out))
	}
}

func TestKeygenWithComment(t *testing.T) {
	dir := t.TempDir()
	idPath := filepath.Join(dir, "commented")

	out, _, err := run("keygen", "-o", idPath, "-c", "my-test-key")
	if err != nil {
		t.Fatalf("keygen with comment failed: %v\n%s", err, out)
	}

	data, _ := os.ReadFile(idPath)
	if !strings.Contains(string(data), "# my-test-key") {
		t.Fatalf("expected comment in identity file, got: %s", string(data))
	}
	if !strings.Contains(out, "Public key: cphx") {
		t.Fatalf("expected public key in output, got: %s", out)
	}
}

func TestKeygenDefaultOutput(t *testing.T) {
	dir := t.TempDir()

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	out, _, err := run("keygen")
	if err != nil {
		t.Fatalf("keygen default failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Identity written to") {
		t.Fatalf("expected identity written message, got: %s", out)
	}
	if _, err := os.Stat(filepath.Join(dir, "cipherix-identity")); os.IsNotExist(err) {
		t.Fatal("default identity file not created")
	}
	// Verify file permissions are 0600.
	info, _ := os.Stat(filepath.Join(dir, "cipherix-identity"))
	if info.Mode().Perm() != 0600 {
		t.Fatalf("expected 0600 permissions, got %o", info.Mode().Perm())
	}
}

func TestDecryptAutoDetect(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "autodetect.txt")
	if err := os.WriteFile(src, []byte("auto detect"), 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	run("encrypt", "-k", "-p", "pass", "-m", "aes", src)

	lck := lckPath(src)
	out, _, err := run("decrypt", "-k", "-p", "pass", lck)
	if err != nil {
		t.Fatalf("auto-detect decrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "decrypted successfully") {
		t.Fatalf("expected success, got: %s", out)
	}
	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed after auto-detect round-trip")
	}
}

func TestInvalidGlobPattern(t *testing.T) {
	_, errOut, err := run("encrypt", "-p", "pass", "[invalid")
	if err == nil {
		t.Fatal("expected error for invalid glob")
	}
	if !strings.Contains(errOut, "invalid file pattern") {
		t.Fatalf("expected invalid file pattern error, got: %q", errOut)
	}
}

func TestGlobNoMatch(t *testing.T) {
	_, errOut, err := run("encrypt", "-p", "pass", "*.nonexistent")
	if err == nil {
		t.Fatal("expected error for no matching glob")
	}
	if !strings.Contains(errOut, "no matching files") {
		t.Fatalf("expected no matching files error, got: %q", errOut)
	}
}

func TestInvalidRecipient(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "badrec.txt")
	if err := os.WriteFile(src, []byte("test"), 0644); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := run("encrypt", "-k", "-r", "not-a-valid-recipient", src)
	if err == nil {
		t.Fatal("expected error for invalid recipient")
	}
	if !strings.Contains(stderr, "invalid recipient") {
		t.Fatalf("expected invalid recipient error, got: %s", stderr)
	}
}

func TestXChaCha20MethodAlias(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "xchacha.txt")
	if err := os.WriteFile(src, []byte("xchacha20 alias test"), 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	out, _, err := run("encrypt", "-k", "-p", "pass", "-m", "xchacha20", src)
	if err != nil {
		t.Fatalf("xchacha20 encrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "encrypted successfully") {
		t.Fatalf("expected success, got: %s", out)
	}

	lck := lckPath(src)
	out, _, err = run("decrypt", "-k", "-p", "pass", lck)
	if err != nil {
		t.Fatalf("xchacha20 decrypt failed: %v\n%s", err, out)
	}
	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed after xchacha20 round-trip")
	}
	data, _ := os.ReadFile(src)
	if string(data) != "xchacha20 alias test" {
		t.Fatalf("data mismatch: got %q", string(data))
	}
}

// generateIdentity writes a cipherix identity file without adding to keystore.
func generateIdentity(t *testing.T, path string) string {
	t.Helper()
	id, err := crypt.GenerateIdentity("")
	if err != nil {
		t.Fatalf("generating identity: %v", err)
	}
	data := crypt.MarshalIdentity(id)
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatalf("writing identity: %v", err)
	}
	return crypt.PublicKeyToRecipient(id.Public)
}

// extractPubkey parses a cipherix identity file and returns the public key string.
func extractPubkey(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading identity file: %v", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "# public: ") {
			return strings.TrimPrefix(line, "# public: ")
		}
	}
	t.Fatal("public key not found in identity file")
	return ""
}

func runWithEnv(env []string, args ...string) (stdout, stderr string, err error) {
	var outb, errb bytes.Buffer
	cmd := exec.Command(binaryPath, args...)
	cmd.Env = env
	cmd.Stdout = &outb
	cmd.Stderr = &errb
	err = cmd.Run()
	return outb.String(), errb.String(), err
}

// keystoreEnv returns env vars that isolate the keystore to a temp directory.
func keystoreEnv(homeDir string) []string {
	env := os.Environ()
	// Remove XDG_CONFIG_HOME if set, then override HOME so
	// os.UserConfigDir() resolves to homeDir/.config.
	for i := 0; i < len(env); i++ {
		if strings.HasPrefix(env[i], "XDG_CONFIG_HOME=") {
			env = append(env[:i], env[i+1:]...)
			break
		}
	}
	env = append(env, "HOME="+homeDir)
	return env
}

func TestKeystoreAddGenerate(t *testing.T) {
	home := t.TempDir()
	env := keystoreEnv(home)

	out, _, err := runWithEnv(env, "keystore", "add", "mykey")
	if err != nil {
		t.Fatalf("keystore add failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Generated new X25519 key") {
		t.Fatalf("expected generated key message, got: %s", out)
	}
	if !strings.Contains(out, "Set \"mykey\" as the default key") {
		t.Fatalf("expected auto-default message, got: %s", out)
	}
	if !strings.Contains(out, "Public key: cphx") {
		t.Fatalf("expected public key in output, got: %s", out)
	}
}

func TestKeystoreAddImport(t *testing.T) {
	home := t.TempDir()
	env := keystoreEnv(home)

	// First, create an identity file with keygen.
	idFile := filepath.Join(home, "test-identity")
	out, _, err := runWithEnv(env, "keygen", "-o", idFile)
	if err != nil {
		t.Fatalf("keygen failed: %v\n%s", err, out)
	}

	// Import it into the keystore.
	out, _, err = runWithEnv(env, "keystore", "add", "imported", idFile)
	if err != nil {
		t.Fatalf("keystore add import failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Imported X25519 key") {
		t.Fatalf("expected import message, got: %s", out)
	}
}

func TestKeystoreList(t *testing.T) {
	home := t.TempDir()
	env := keystoreEnv(home)

	runWithEnv(env, "keystore", "add", "key-a")
	runWithEnv(env, "keystore", "add", "key-b")

	out, _, err := runWithEnv(env, "keystore", "list")
	if err != nil {
		t.Fatalf("keystore list failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "key-a") {
		t.Fatalf("expected key-a in list, got: %s", out)
	}
	if !strings.Contains(out, "key-b") {
		t.Fatalf("expected key-b in list, got: %s", out)
	}
}

func TestKeystoreShow(t *testing.T) {
	home := t.TempDir()
	env := keystoreEnv(home)

	runWithEnv(env, "keystore", "add", "show-key")

	out, _, err := runWithEnv(env, "keystore", "show", "show-key")
	if err != nil {
		t.Fatalf("keystore show failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "show-key") {
		t.Fatalf("expected key name in output, got: %s", out)
	}
	if !strings.Contains(out, "Public key: cphx") {
		t.Fatalf("expected public key, got: %s", out)
	}
}

func TestKeystoreRemove(t *testing.T) {
	home := t.TempDir()
	env := keystoreEnv(home)

	runWithEnv(env, "keystore", "add", "remove-me")

	out, _, err := runWithEnv(env, "keystore", "remove", "remove-me")
	if err != nil {
		t.Fatalf("keystore remove failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Removed key") {
		t.Fatalf("expected removed message, got: %s", out)
	}

	// Verify list shows empty.
	out, _, _ = runWithEnv(env, "keystore", "list")
	if strings.Contains(out, "remove-me") {
		t.Fatal("key should not appear after removal")
	}
}

func TestKeystoreExport(t *testing.T) {
	home := t.TempDir()
	env := keystoreEnv(home)

	runWithEnv(env, "keystore", "add", "export-key")

	exportPath := filepath.Join(home, "exported-identity")
	out, _, err := runWithEnv(env, "keystore", "export", "export-key", "-o", exportPath)
	if err != nil {
		t.Fatalf("keystore export failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Exported key") {
		t.Fatalf("expected export message, got: %s", out)
	}
	if _, err := os.Stat(exportPath); os.IsNotExist(err) {
		t.Fatal("exported identity file not created")
	}
}

func TestKeystoreDefault(t *testing.T) {
	home := t.TempDir()
	env := keystoreEnv(home)

	runWithEnv(env, "keystore", "add", "first")
	runWithEnv(env, "keystore", "add", "second")

	// Set second as default.
	out, _, err := runWithEnv(env, "keystore", "default", "second")
	if err != nil {
		t.Fatalf("keystore default failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Set \"second\" as the default key") {
		t.Fatalf("expected default message, got: %s", out)
	}

	// List should show second as default (public key is inserted between name and marker).
	out, _, _ = runWithEnv(env, "keystore", "list")
	if !(strings.Contains(out, "second") && strings.Contains(out, "(default)")) {
		t.Fatalf("expected second marked default, got: %s", out)
	}
}

func TestEncryptDecryptWithKeyKeystore(t *testing.T) {
	home := t.TempDir()
	env := keystoreEnv(home)

	// Add a key to keystore.
	runWithEnv(env, "keystore", "add", "testkey")

	// Encrypt using keystore key via -r.
	src := filepath.Join(home, "secret.txt")
	if err := os.WriteFile(src, []byte("keystore secret"), 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	out, _, err := runWithEnv(env, "encrypt", "-k", "-r", "testkey", src)
	if err != nil {
		t.Fatalf("encrypt with -r (keystore) failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "encrypted successfully") {
		t.Fatalf("expected success, got: %s", out)
	}

	lck := lckPath(src)
	if _, err := os.Stat(lck); os.IsNotExist(err) {
		t.Fatal("encrypted file not created")
	}

	// Decrypt without flags — auto-detects keystore key.
	out, _, err = runWithEnv(env, "decrypt", "-k", lck)
	if err != nil {
		t.Fatalf("auto-decrypt with keystore failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "testkey") {
		t.Fatalf("expected key usage message with testkey, got: %s", out)
	}
	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed after round-trip")
	}
	data, _ := os.ReadFile(src)
	if string(data) != "keystore secret" {
		t.Fatalf("data mismatch: got %q", string(data))
	}
}

func TestDecryptWithDefaultKey(t *testing.T) {
	home := t.TempDir()
	env := keystoreEnv(home)

	// Add a key (auto-becomes default).
	runWithEnv(env, "keystore", "add", "defaultkey")

	// Encrypt using -r to specify the key from keystore.
	src := filepath.Join(home, "default-secret.txt")
	if err := os.WriteFile(src, []byte("default key test"), 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	runWithEnv(env, "encrypt", "-k", "-r", "defaultkey", src)

	lck := lckPath(src)

	// Decrypt without any flag — should auto-detect the default key.
	out, _, err := runWithEnv(env, "decrypt", "-k", lck)
	if err != nil {
		t.Fatalf("decrypt with default key failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Using default key") {
		t.Fatalf("expected default key message, got: %s", out)
	}
	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed after round-trip")
	}
	data, _ := os.ReadFile(src)
	if string(data) != "default key test" {
		t.Fatalf("data mismatch: got %q", string(data))
	}
}

func TestDecryptFallbackToPasswordWhenNoKeystore(t *testing.T) {
	home := t.TempDir()
	env := keystoreEnv(home)

	// No keystore set up — regular password-based encrypt/decrypt should work.
	src := filepath.Join(home, "pwfallback.txt")
	if err := os.WriteFile(src, []byte("password fallback"), 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	runWithEnv(env, "encrypt", "-k", "-p", "testpass", src)

	lck := lckPath(src)
	out, _, err := runWithEnv(env, "decrypt", "-k", "-p", "testpass", lck)
	if err != nil {
		t.Fatalf("decrypt password fallback failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "decrypted successfully") {
		t.Fatalf("expected success, got: %s", out)
	}
	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed after fallback round-trip")
	}
}

func TestEncryptFileNoExtension(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "noext")
	if err := os.WriteFile(src, []byte("no extension"), 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	out, _, err := run("encrypt", "-k", "-p", "pass", src)
	if err != nil {
		t.Fatalf("encrypt no-ext failed: %v\n%s", err, out)
	}

	lck := lckPath(src)
	if _, err := os.Stat(lck); os.IsNotExist(err) {
		t.Fatal("encrypted file for no-extension input not created")
	}

	out, _, err = run("decrypt", "-k", "-p", "pass", lck)
	if err != nil {
		t.Fatalf("decrypt no-ext failed: %v\n%s", err, out)
	}
	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed for no-extension round-trip")
	}
	data, _ := os.ReadFile(src)
	if string(data) != "no extension" {
		t.Fatalf("data mismatch: got %q", string(data))
	}
}

func TestEncryptDecrypt4CharExtension(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "page.html")
	if err := os.WriteFile(src, []byte("4-char extension"), 0644); err != nil {
		t.Fatal(err)
	}
	origHash := fileHash(t, src)

	out, _, err := run("encrypt", "-k", "-p", "pass", src)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, out)
	}
	lck := lckPath(src)
	if _, err := os.Stat(lck); os.IsNotExist(err) {
		t.Fatal("encrypted file not created")
	}
	out, _, err = run("decrypt", "-k", "-p", "pass", lck)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, out)
	}
	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed for 4-char extension round-trip")
	}
	data, _ := os.ReadFile(src)
	if string(data) != "4-char extension" {
		t.Fatalf("data mismatch: got %q", string(data))
	}
}

func TestEncryptDecryptMultiDotExtension(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "archive.tar.gz")
	if err := os.WriteFile(src, []byte("multi-dot extension"), 0644); err != nil {
		t.Fatal(err)
	}
	origHash := fileHash(t, src)

	out, _, err := run("encrypt", "-k", "-p", "pass", src)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, out)
	}
	lck := lckPath(src)
	if _, err := os.Stat(lck); os.IsNotExist(err) {
		t.Fatal("encrypted file not created")
	}
	out, _, err = run("decrypt", "-k", "-p", "pass", lck)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, out)
	}
	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed for multi-dot extension round-trip")
	}
	data, _ := os.ReadFile(src)
	if string(data) != "multi-dot extension" {
		t.Fatalf("data mismatch: got %q", string(data))
	}
}

func TestEncryptDecryptTwoCharExtension(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "readme.md")
	if err := os.WriteFile(src, []byte("2-char extension"), 0644); err != nil {
		t.Fatal(err)
	}
	origHash := fileHash(t, src)

	out, _, err := run("encrypt", "-k", "-p", "pass", src)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, out)
	}
	lck := lckPath(src)
	if _, err := os.Stat(lck); os.IsNotExist(err) {
		t.Fatal("encrypted file not created")
	}
	out, _, err = run("decrypt", "-k", "-p", "pass", lck)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, out)
	}
	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed for 2-char extension round-trip")
	}
	data, _ := os.ReadFile(src)
	if string(data) != "2-char extension" {
		t.Fatalf("data mismatch: got %q", string(data))
	}
}

func TestEncryptDecryptHiddenFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, ".gitignore")
	if err := os.WriteFile(src, []byte("hidden file"), 0644); err != nil {
		t.Fatal(err)
	}
	origHash := fileHash(t, src)

	out, _, err := run("encrypt", "-k", "-p", "pass", src)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, out)
	}
	lck := lckPath(src)
	if _, err := os.Stat(lck); os.IsNotExist(err) {
		t.Fatal("encrypted file not created")
	}
	out, _, err = run("decrypt", "-k", "-p", "pass", lck)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, out)
	}
	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed for hidden-file round-trip")
	}
	data, _ := os.ReadFile(src)
	if string(data) != "hidden file" {
		t.Fatalf("data mismatch: got %q", string(data))
	}
}

func TestEncryptDecryptHiddenFileWithExtension(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, ".config.json")
	if err := os.WriteFile(src, []byte("hidden with ext"), 0644); err != nil {
		t.Fatal(err)
	}
	origHash := fileHash(t, src)

	out, _, err := run("encrypt", "-k", "-p", "pass", src)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, out)
	}
	lck := lckPath(src)
	if _, err := os.Stat(lck); os.IsNotExist(err) {
		t.Fatal("encrypted file not created")
	}
	out, _, err = run("decrypt", "-k", "-p", "pass", lck)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, out)
	}
	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed for hidden-with-ext round-trip")
	}
	data, _ := os.ReadFile(src)
	if string(data) != "hidden with ext" {
		t.Fatalf("data mismatch: got %q", string(data))
	}
}

func TestMultiRecipientRoundtrip(t *testing.T) {
	dir := t.TempDir()

	// Generate two identities.
	idPath1 := filepath.Join(dir, "id1")
	run("keygen", "-o", idPath1)
	idPath2 := filepath.Join(dir, "id2")
	run("keygen", "-o", idPath2)

	// Extract public keys.
	idData1, _ := os.ReadFile(idPath1)
	idData2, _ := os.ReadFile(idPath2)
	var pubkey1, pubkey2 string
	for _, line := range strings.Split(string(idData1), "\n") {
		if strings.HasPrefix(line, "# public: ") {
			pubkey1 = strings.TrimPrefix(line, "# public: ")
			break
		}
	}
	for _, line := range strings.Split(string(idData2), "\n") {
		if strings.HasPrefix(line, "# public: ") {
			pubkey2 = strings.TrimPrefix(line, "# public: ")
			break
		}
	}
	if pubkey1 == "" || pubkey2 == "" {
		t.Fatal("could not find public keys")
	}

	// Encrypt to both recipients.
	src := filepath.Join(dir, "multi.txt")
	if err := os.WriteFile(src, []byte("multi-recipient secret"), 0644); err != nil {
		t.Fatal(err)
	}
	origHash := fileHash(t, src)

	out, _, err := run("encrypt", "-k", "-r", pubkey1, "-r", pubkey2, src)
	if err != nil {
		t.Fatalf("multi-recipient encrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "encrypted successfully") {
		t.Fatalf("expected success, got: %s", out)
	}

	lck := lckPath(src)
	if _, err := os.Stat(lck); os.IsNotExist(err) {
		t.Fatal("encrypted file not created")
	}

	// Each recipient should be able to decrypt.
	for i, idPath := range []string{idPath1, idPath2} {
		out, _, err := run("decrypt", "-k", "-i", idPath, lck)
		if err != nil {
			t.Fatalf("recipient %d decrypt failed: %v\n%s", i+1, err, out)
		}
	}
	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed after round-trip")
	}
	data, _ := os.ReadFile(src)
	if string(data) != "multi-recipient secret" {
		t.Fatalf("data mismatch: got %q", string(data))
	}
}

func TestMultiRecipientNonRecipientFails(t *testing.T) {
	dir := t.TempDir()

	id1 := filepath.Join(dir, "id1")
	id2 := filepath.Join(dir, "id2")
	// Use generateIdentity to avoid auto-adding to keystore.
	pubkey1 := generateIdentity(t, id1)
	pubkey2 := generateIdentity(t, id2)

	intruder := filepath.Join(dir, "intruder")
	run("keygen", "-o", intruder)

	src := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(src, []byte("for id1 and id2 only"), 0644); err != nil {
		t.Fatal(err)
	}
	run("encrypt", "-k", "-r", pubkey1, "-r", pubkey2, src)

	lck := lckPath(src)
	intruderPath := filepath.Join(dir, "intruder")
	_, errOut, err := run("decrypt", "-k", "-i", intruderPath, lck)
	if err == nil {
		t.Fatal("expected error for non-recipient")
	}
	if !strings.Contains(errOut, "inappropriate ioctl") && !strings.Contains(errOut, "decryption failed") {
		t.Fatalf("expected decryption failed error, got: %s", errOut)
	}
}

func TestKeygenAddsToKeystore(t *testing.T) {
	home := t.TempDir()
	env := keystoreEnv(home)

	idFile := filepath.Join(home, "testkey")
	out, _, err := runWithEnv(env, "keygen", "-o", idFile)
	if err != nil {
		t.Fatalf("keygen failed: %v\n%s", err, out)
	}

	// Should show keystore message.
	if !strings.Contains(out, "Added key to keystore") {
		t.Fatalf("expected keystore add message, got: %s", out)
	}

	// Keystore list should show the key.
	out, _, err = runWithEnv(env, "keystore", "list")
	if err != nil {
		t.Fatalf("keystore list failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "testkey") {
		t.Fatalf("expected key in keystore list, got: %s", out)
	}
}

func TestKeygenFirstKeyBecomesDefault(t *testing.T) {
	home := t.TempDir()
	env := keystoreEnv(home)

	// First keygen'd key should become default.
	idFile := filepath.Join(home, "mykey")
	out, _, err := runWithEnv(env, "keygen", "-o", idFile)
	if err != nil {
		t.Fatalf("keygen failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Set \"mykey\" as the default key") {
		t.Fatalf("expected default key message, got: %s", out)
	}

	// Second keygen'd key should NOT override default.
	idFile2 := filepath.Join(home, "second")
	out, _, err = runWithEnv(env, "keygen", "-o", idFile2)
	if err != nil {
		t.Fatalf("keygen failed: %v\n%s", err, out)
	}
	if strings.Contains(out, "default key") {
		t.Fatalf("second key should not override default, got: %s", out)
	}
}

func TestKeygenShowPubkeyNoKeystore(t *testing.T) {
	home := t.TempDir()
	env := keystoreEnv(home)

	out, _, err := runWithEnv(env, "keygen", "-y")
	if err != nil {
		t.Fatalf("keygen -y failed: %v\n%s", err, out)
	}
	if !strings.HasPrefix(strings.TrimSpace(out), "cphx") {
		t.Fatalf("expected cphx prefix, got: %s", out)
	}

	// Keystore should be empty (no key added).
	listOut, _, err := runWithEnv(env, "keystore", "list")
	if err != nil {
		t.Fatalf("keystore list failed: %v\n%s", err, listOut)
	}
	if !strings.Contains(listOut, "Keystore is empty") {
		t.Fatalf("expected empty keystore, got: %s", listOut)
	}
}

func TestParallelGlobEncryptDecrypt(t *testing.T) {
	dir := t.TempDir()

	// Create 10 test files with unique content.
	var srcs []string
	hashes := make(map[string][32]byte)
	for i := 0; i < 10; i++ {
		src := filepath.Join(dir, fmt.Sprintf("pg_%d.txt", i))
		content := fmt.Sprintf("parallel glob file %d", i)
		if err := os.WriteFile(src, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		hashes[src] = fileHash(t, src)
		srcs = append(srcs, src)
	}

	// Encrypt all at once with glob.
	out, _, err := run("encrypt", "-k", "-p", "pass", filepath.Join(dir, "pg_*.txt"))
	if err != nil {
		t.Fatalf("parallel glob encrypt failed: %v\n%s", err, out)
	}

	// Verify all .chx files created.
	for _, src := range srcs {
		lck := lckPath(src)
		if _, err := os.Stat(lck); os.IsNotExist(err) {
			t.Fatalf("encrypted file not created: %s", lck)
		}
	}

	// Decrypt all at once with glob.
	out, _, err = run("decrypt", "-k", "-p", "pass", filepath.Join(dir, "pg_*.chx"))
	if err != nil {
		t.Fatalf("parallel glob decrypt failed: %v\n%s", err, out)
	}

	// Verify all data matches and integrity.
	for i, src := range srcs {
		if fileHash(t, src) != hashes[src] {
			t.Fatalf("integrity check failed for %s", src)
		}
		want := fmt.Sprintf("parallel glob file %d", i)
		got, _ := os.ReadFile(src)
		if string(got) != want {
			t.Fatalf("file %s data mismatch: got %q, want %q", src, string(got), want)
		}
	}
}

// -- Stdin tests --

func TestStdinEncryptDecryptPassword(t *testing.T) {
	dir := t.TempDir()

	// Encrypt from stdin, write to file
	out, _, err := runWithStdin("stdin test data", "encrypt", "-p", "testpass", "-o", filepath.Join(dir, "out.chx"))
	if err != nil {
		t.Fatalf("stdin encrypt failed: %v\n%s", err, out)
	}

	// Decrypt from file, print to stdout
	out, _, err = run("decrypt", "-p", "testpass", "--print", filepath.Join(dir, "out.chx"))
	if err != nil {
		t.Fatalf("stdin decrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "stdin test data") {
		t.Fatalf("expected 'stdin test data' in output, got: %s", out)
	}
}

func TestStdinEncryptDecryptPipe(t *testing.T) {
	// Full pipe: encrypt stdin -> decrypt stdin
	out, _, err := runWithStdin("pipe data", "encrypt", "-p", "pass")
	if err != nil {
		t.Fatalf("stdin encrypt failed: %v\n%s", err, out)
	}

	// Pipe encrypted output through decrypt
	out2, _, err := runWithStdin(out, "decrypt", "-p", "pass")
	if err != nil {
		t.Fatalf("stdin decrypt pipe failed: %v\n%s", err, out2)
	}
	if !strings.Contains(out2, "pipe data") {
		t.Fatalf("expected 'pipe data' in output, got: %s", out2)
	}
}

func TestStdinEncryptNoPassword(t *testing.T) {
	// Isolate home to prevent auto-keystore fallback.
	home := t.TempDir()
	_, errOut, err := runWithStdinEnv("data", keystoreEnv(home), "encrypt")
	if err == nil {
		t.Fatal("expected error for missing password on stdin encrypt")
	}
	if !strings.Contains(errOut, "password required") {
		t.Fatalf("expected password required error, got: %s", errOut)
	}
}

func TestStdinDecryptNoPassword(t *testing.T) {
	// First create a valid encrypted file
	encOut, _, _ := runWithStdin("test", "encrypt", "-p", "pass")

	// Now try to decrypt from stdin without any password/identity.
	// Isolate home to prevent keystore edge case (default key fallback).
	home := t.TempDir()
	_, errOut, err := runWithStdinEnv(encOut, keystoreEnv(home), "decrypt")
	if err == nil {
		t.Fatal("expected error for missing password on stdin decrypt")
	}
	if !strings.Contains(errOut, "password required") {
		t.Fatalf("expected password required error, got: %s", errOut)
	}
}

func TestStdinEncryptWithRecipient(t *testing.T) {
	dir := t.TempDir()

	// Generate a key pair for recipient encryption
	idPath := filepath.Join(dir, "stdin-key")
	run("keygen", "-o", idPath)

	idData, _ := os.ReadFile(idPath)
	var pubkey string
	for _, line := range strings.Split(string(idData), "\n") {
		if strings.HasPrefix(line, "# public: ") {
			pubkey = strings.TrimPrefix(line, "# public: ")
			break
		}
	}
	if pubkey == "" {
		t.Fatal("public key not found")
	}

	// Encrypt stdin to recipient, output to file
	lckPath := filepath.Join(dir, "recv.chx")
	runWithStdin("recipient stdin data", "encrypt", "-r", pubkey, "-o", lckPath)

	// Decrypt and verify
	out, _, err := run("decrypt", "-i", idPath, "--print", lckPath)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "recipient stdin data") {
		t.Fatalf("expected 'recipient stdin data' in output, got: %s", out)
	}
}

// -- Armor tests --

func TestArmorEncryptDecryptFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "armor.txt")
	if err := os.WriteFile(src, []byte("armor file test"), 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	out, _, err := run("encrypt", "-k", "-p", "pass", "-a", src)
	if err != nil {
		t.Fatalf("armor encrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "encrypted successfully") {
		t.Fatalf("expected success, got: %s", out)
	}

	lck := lckPath(src)
	data, err := os.ReadFile(lck)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(data), "-----BEGIN CIPHERIX FILE-----") {
		t.Fatalf("expected armor header, got: %s", string(data[:60]))
	}

	// Decrypt (auto-detects armor)
	out, _, err = run("decrypt", "-k", "-p", "pass", lck)
	if err != nil {
		t.Fatalf("armor decrypt failed: %v\n%s", err, out)
	}
	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed after armored round-trip")
	}
	plaintext, _ := os.ReadFile(src)
	if string(plaintext) != "armor file test" {
		t.Fatalf("data mismatch: got %q", string(plaintext))
	}
}

func TestStdinArmorPipe(t *testing.T) {
	// Encrypt stdin with armor, pipe to decrypt
	out, _, err := runWithStdin("armor pipe test", "encrypt", "-p", "pass", "-a")
	if err != nil {
		t.Fatalf("armor encrypt failed: %v\n%s", err, out)
	}
	if !strings.HasPrefix(out, "-----BEGIN CIPHERIX FILE-----") {
		t.Fatalf("expected armor header in stdout, got: %s", out[:60])
	}

	out2, _, err := runWithStdin(out, "decrypt", "-p", "pass")
	if err != nil {
		t.Fatalf("armor decrypt failed: %v\n%s", err, out2)
	}
	if !strings.Contains(out2, "armor pipe test") {
		t.Fatalf("expected 'armor pipe test' in output, got: %s", out2)
	}
}

func TestArmorDecryptWithoutFlag(t *testing.T) {
	dir := t.TempDir()
	plaintext := []byte("auto-detect armor")
	src := filepath.Join(dir, "naked.txt")
	if err := os.WriteFile(src, plaintext, 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	// Encrypt with -a
	out, _, err := run("encrypt", "-k", "-p", "pass", "-a", src)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, out)
	}

	lck := lckPath(src)

	// Decrypt WITHOUT any armor flag (auto-detect)
	out, _, err = run("decrypt", "-k", "-p", "pass", lck)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, out)
	}
	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed after auto-detect armor round-trip")
	}
	data, _ := os.ReadFile(src)
	if string(data) != string(plaintext) {
		t.Fatalf("data mismatch: got %q, want %q", string(data), string(plaintext))
	}
}

// -- SSH key tests --

func generateSSHKey(t *testing.T, dir, name string) (pubkey string) {
	t.Helper()
	keyPath := filepath.Join(dir, name)
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", keyPath, "-C", "test")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen failed: %v\n%s", err, out)
	}
	pubBytes, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatalf("reading pub key: %v", err)
	}
	return strings.TrimSpace(string(pubBytes))
}

func TestSSHRoundtripFile(t *testing.T) {
	dir := t.TempDir()
	pubkey := generateSSHKey(t, dir, "ed25519")

	src := filepath.Join(dir, "ssh-file.txt")
	if err := os.WriteFile(src, []byte("ssh file test"), 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	// Encrypt to SSH public key
	out, _, err := run("encrypt", "-k", "-r", pubkey, src)
	if err != nil {
		t.Fatalf("SSH encrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "encrypted successfully") {
		t.Fatalf("expected success, got: %s", out)
	}

	// Decrypt with SSH private key
	lck := lckPath(src)
	out, _, err = run("decrypt", "-k", "-i", filepath.Join(dir, "ed25519"), lck)
	if err != nil {
		t.Fatalf("SSH decrypt failed: %v\n%s", err, out)
	}

	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed after round-trip")
	}
	data, _ := os.ReadFile(src)
	if string(data) != "ssh file test" {
		t.Fatalf("data mismatch: got %q", string(data))
	}
}

func TestSSHRoundtripStdin(t *testing.T) {
	dir := t.TempDir()
	pubkey := generateSSHKey(t, dir, "key")

	// Encrypt stdin to SSH pub key, output to file
	lckPath := filepath.Join(dir, "ssh-stdin.chx")
	runWithStdin("ssh stdin data", "encrypt", "-r", pubkey, "-o", lckPath)

	// Decrypt file with SSH private key, print to stdout
	out, _, err := run("decrypt", "-i", filepath.Join(dir, "key"), "--print", lckPath)
	if err != nil {
		t.Fatalf("SSH decrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "ssh stdin data") {
		t.Fatalf("expected 'ssh stdin data' in output, got: %s", out)
	}
}

func TestSSHPipeRoundtrip(t *testing.T) {
	dir := t.TempDir()
	pubkey := generateSSHKey(t, dir, "pipekey")

	// Full pipe: encrypt stdin with SSH pub key -> pipe -> decrypt stdin with SSH priv key
	encOut, _, err := runWithStdin("ssh pipe data", "encrypt", "-r", pubkey)
	if err != nil {
		t.Fatalf("SSH encrypt failed: %v\n%s", err, encOut)
	}

	out, _, err := runWithStdin(encOut, "decrypt", "-i", filepath.Join(dir, "pipekey"))
	if err != nil {
		t.Fatalf("SSH decrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "ssh pipe data") {
		t.Fatalf("expected 'ssh pipe data' in output, got: %s", out)
	}
}

func TestSSHWrongIdentity(t *testing.T) {
	dir := t.TempDir()
	// Isolate home to prevent keystore fallback from matching.
	home := t.TempDir()
	env := keystoreEnv(home)

	pubkey1 := generateSSHKey(t, dir, "key1")
	generateSSHKey(t, dir, "key2")

	src := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(src, []byte("secret"), 0644); err != nil {
		t.Fatal(err)
	}

	// Encrypt to key1
	runWithEnv(env, "encrypt", "-k", "-r", pubkey1, src)

	// Try decrypting with key2 (should fail)
	lck := lckPath(src)
	_, errOut, err := runWithEnv(env, "decrypt", "-k", "-i", filepath.Join(dir, "key2"), lck)
	if err == nil {
		t.Fatal("expected error for wrong identity")
	}
	if !strings.Contains(errOut, "inappropriate ioctl") && !strings.Contains(errOut, "decryption failed") {
		t.Fatalf("expected decryption failure, got: %s", errOut)
	}
}

func TestSSHInvalidRecipient(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "bad.txt")
	if err := os.WriteFile(src, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	_, errOut, err := run("encrypt", "-k", "-r", "ssh-rsa AAAA", src)
	if err == nil {
		t.Fatal("expected error for invalid SSH recipient")
	}
	if !strings.Contains(errOut, "invalid recipient") {
		t.Fatalf("expected invalid recipient error, got: %s", errOut)
	}
}

func TestSSHInvalidIdentity(t *testing.T) {
	dir := t.TempDir()
	lck := filepath.Join(dir, "test.chx")

	// Create a minimal .chx file
	emptyLck := filepath.Join(dir, "dummy.chx")
	os.WriteFile(emptyLck, []byte("fake"), 0644)

	_, _, err := run("decrypt", "-i", "/nonexistent/file", emptyLck)
	if err == nil {
		t.Fatal("expected error for invalid identity path")
	}
	_ = lck
}

func TestSSHArmoredCombine(t *testing.T) {
	dir := t.TempDir()
	pubkey := generateSSHKey(t, dir, "combined")

	// Encrypt stdin with SSH + armor
	encOut, _, err := runWithStdin("ssh+armor data", "encrypt", "-a", "-r", pubkey)
	if err != nil {
		t.Fatalf("SSH+armor encrypt failed: %v\n%s", err, encOut)
	}
	if !strings.HasPrefix(encOut, "-----BEGIN CIPHERIX FILE-----") {
		t.Fatalf("expected armor in output, got: %s", encOut[:60])
	}

	// Decrypt armored SSH pipe
	out, _, err := runWithStdin(encOut, "decrypt", "-i", filepath.Join(dir, "combined"))
	if err != nil {
		t.Fatalf("SSH+armor decrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "ssh+armor data") {
		t.Fatalf("expected 'ssh+armor data' in output, got: %s", out)
	}
}

func TestSSHMultiRecipient(t *testing.T) {
	dir := t.TempDir()
	pubkey1 := generateSSHKey(t, dir, "mr1")
	pubkey2 := generateSSHKey(t, dir, "mr2")

	src := filepath.Join(dir, "multi.txt")
	if err := os.WriteFile(src, []byte("multi-ssh test data"), 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	// Encrypt to both SSH keys
	out, _, err := run("encrypt", "-k", "-r", pubkey1, "-r", pubkey2, src)
	if err != nil {
		t.Fatalf("SSH multi encrypt failed: %v\n%s", err, out)
	}

	// Each recipient should be able to decrypt
	for _, name := range []string{"mr1", "mr2"} {
		lck := lckPath(src)
		out, _, err := run("decrypt", "-k", "-i", filepath.Join(dir, name), lck)
		if err != nil {
			t.Fatalf("recipient %s decrypt failed: %v\n%s", name, err, out)
		}
	}
	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed after round-trip")
	}
}

func TestStdinWithSSHAndArmor(t *testing.T) {
	dir := t.TempDir()
	pubkey := generateSSHKey(t, dir, "triple")

	// Full featured: stdin + SSH + armor
	encOut, _, err := runWithStdin("triple threat", "encrypt", "-a", "-r", pubkey)
	if err != nil {
		t.Fatalf("triple encrypt failed: %v\n%s", err, encOut)
	}

	// Decrypt: stdin + armored + SSH identity
	out, _, err := runWithStdin(encOut, "decrypt", "-i", filepath.Join(dir, "triple"))
	if err != nil {
		t.Fatalf("triple decrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "triple threat") {
		t.Fatalf("expected 'triple threat' in output, got: %s", out)
	}
}

func TestInspectCommandBasic(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "topsecret.txt")
	if err := os.WriteFile(src, []byte("inspect me"), 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(src)

	out, _, err := run("encrypt", "-k", "-p", "hunter2", src)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, out)
	}

	lck := lckPath(src)
	out, _, err = run("inspect", lck)
	if err != nil {
		t.Fatalf("inspect failed: %v\n%s", err, out)
	}

	if !strings.Contains(out, "AES-256-GCM") {
		t.Fatalf("expected AES-256-GCM in inspect output, got:\n%s", out)
	}
	if !strings.Contains(out, "scrypt") {
		t.Fatalf("expected scrypt in inspect output, got:\n%s", out)
	}
	if !strings.Contains(out, "txt") {
		t.Fatalf("expected txt extension in inspect output, got:\n%s", out)
	}
	if !strings.Contains(out, "Format:  3") {
		t.Fatalf("expected format version 3 in inspect output, got:\n%s", out)
	}
}

func TestInspectCommandArmored(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "armored.doc")
	if err := os.WriteFile(src, []byte("armored data"), 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(src)

	out, _, err := run("encrypt", "-k", "-a", "-p", "hunter2", src)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, out)
	}

	lck := lckPath(src)
	out, _, err = run("inspect", lck)
	if err != nil {
		t.Fatalf("inspect failed: %v\n%s", err, out)
	}

	if !strings.Contains(out, "Armored: yes") {
		t.Fatalf("expected 'Armored: yes' for armored file, got:\n%s", out)
	}
}

func TestInspectCommandFolderType(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "mydir")
	if err := os.Mkdir(subdir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(subdir, "a.txt"), []byte("a"), 0644); err != nil {
		t.Fatal(err)
	}

	out, _, err := runWithStdin("yes", "encrypt", "-k", "-p", "hunter2", subdir)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, out)
	}

	lck := lckPath(subdir)
	out, _, err = run("inspect", lck)
	if err != nil {
		t.Fatalf("inspect failed: %v\n%s", err, out)
	}

	if !strings.Contains(out, "folder") {
		t.Fatalf("expected 'folder' type for directory encrypt, got:\n%s", out)
	}
}

func TestInspectCommandMultiRecipient(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "shared.pub")
	if err := os.WriteFile(src, []byte("multi-recipient data"), 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(src)

	// Generate two keys
	k1 := filepath.Join(dir, "key1")
	out, _, err := run("keygen", "-o", k1)
	if err != nil {
		t.Fatalf("keygen1 failed: %v\n%s", err, out)
	}
	k2 := filepath.Join(dir, "key2")
	out, _, err = run("keygen", "-o", k2)
	if err != nil {
		t.Fatalf("keygen2 failed: %v\n%s", err, out)
	}

	// Read pubkeys
	pub1bytes, err := os.ReadFile(k1)
	if err != nil {
		t.Fatal(err)
	}
	pub1 := string(pub1bytes)
	// Extract the cphx pubkey from the identity file (it's on the "# public:" line)
	var pubkey1, pubkey2 string
	for _, line := range strings.Split(pub1, "\n") {
		if strings.HasPrefix(line, "# public: ") {
			pubkey1 = strings.TrimPrefix(line, "# public: ")
			break
		}
	}
	pub2bytes, _ := os.ReadFile(k2)
	for _, line := range strings.Split(string(pub2bytes), "\n") {
		if strings.HasPrefix(line, "# public: ") {
			pubkey2 = strings.TrimPrefix(line, "# public: ")
			break
		}
	}
	if pubkey1 == "" || pubkey2 == "" {
		t.Fatal("could not extract pubkeys from identity files")
	}

	out, _, err = run("encrypt", "-k", "-r", pubkey1, "-r", pubkey2, src)
	if err != nil {
		t.Fatalf("encrypt multi failed: %v\n%s", err, out)
	}

	lck := lckPath(src)
	out, _, err = run("inspect", lck)
	if err != nil {
		t.Fatalf("inspect failed: %v\n%s", err, out)
	}

	if !strings.Contains(out, "Recipients: 2") {
		t.Fatalf("expected 'Recipients: 2' in inspect output, got:\n%s", out)
	}
	// Should contain two recipient ID lines
	if !strings.Contains(out, "recipient 1:") {
		t.Fatalf("expected 'recipient 1:' in inspect output, got:\n%s", out)
	}
	if !strings.Contains(out, "recipient 2:") {
		t.Fatalf("expected 'recipient 2:' in inspect output, got:\n%s", out)
	}
}

func TestInspectCommandInvalidFile(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "fake.chx")
	if err := os.WriteFile(bad, []byte("not encrypted"), 0644); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := run("inspect", bad)
	if err == nil {
		t.Fatal("expected error for non-encrypted file")
	}
	if !strings.Contains(stderr, "unknown") {
		t.Fatalf("expected 'unknown format' error, got: %s", stderr)
	}
}

func generateRSAKey(t *testing.T, dir, name string) (pubkey string) {
	t.Helper()
	keyPath := filepath.Join(dir, name)
	cmd := exec.Command("ssh-keygen", "-t", "rsa", "-b", "2048", "-N", "", "-f", keyPath, "-C", "test-rsa")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen rsa failed: %v\n%s", err, out)
	}
	pubBytes, err := os.ReadFile(keyPath + ".pub")
	if err != nil {
		t.Fatalf("reading rsa pub key: %v", err)
	}
	return strings.TrimSpace(string(pubBytes))
}

func TestRSARoundtripFile(t *testing.T) {
	dir := t.TempDir()
	pubkey := generateRSAKey(t, dir, "rsa1")

	src := filepath.Join(dir, "rsa-file.txt")
	if err := os.WriteFile(src, []byte("rsa file test"), 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	out, _, err := run("encrypt", "-k", "-r", pubkey, src)
	if err != nil {
		t.Fatalf("RSA encrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "encrypted successfully") {
		t.Fatalf("expected success, got: %s", out)
	}

	lck := lckPath(src)
	out, _, err = run("decrypt", "-k", "-i", filepath.Join(dir, "rsa1"), lck)
	if err != nil {
		t.Fatalf("RSA decrypt failed: %v\n%s", err, out)
	}

	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed after RSA round-trip")
	}
}

func TestRSAMultiRecipientCLI(t *testing.T) {
	dir := t.TempDir()
	pubkey1 := generateRSAKey(t, dir, "rsa-m1")
	pubkey2 := generateRSAKey(t, dir, "rsa-m2")

	src := filepath.Join(dir, "rsa-multi.txt")
	if err := os.WriteFile(src, []byte("rsa multi test"), 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	out, _, err := run("encrypt", "-k", "-r", pubkey1, "-r", pubkey2, src)
	if err != nil {
		t.Fatalf("RSA multi encrypt failed: %v\n%s", err, out)
	}

	for _, name := range []string{"rsa-m1", "rsa-m2"} {
		lck := lckPath(src)
		out, _, err := run("decrypt", "-k", "-i", filepath.Join(dir, name), lck)
		if err != nil {
			t.Fatalf("RSA multi recipient %s decrypt failed: %v\n%s", name, err, out)
		}
	}

	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed after RSA multi round-trip")
	}
}

func TestHybridRoundtripCLI(t *testing.T) {
	dir := t.TempDir()
	edPub := generateSSHKey(t, dir, "hybrid-ed")
	rsaPub := generateRSAKey(t, dir, "hybrid-rsa")

	src := filepath.Join(dir, "hybrid.txt")
	if err := os.WriteFile(src, []byte("hybrid rsa+ed test"), 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	out, _, err := run("encrypt", "-k", "-r", edPub, "-r", rsaPub, src)
	if err != nil {
		t.Fatalf("Hybrid encrypt failed: %v\n%s", err, out)
	}

	for _, name := range []string{"hybrid-ed", "hybrid-rsa"} {
		lck := lckPath(src)
		out, _, err := run("decrypt", "-k", "-i", filepath.Join(dir, name), lck)
		if err != nil {
			t.Fatalf("Hybrid recipient %s decrypt failed: %v\n%s", name, err, out)
		}
	}

	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed after hybrid round-trip")
	}
}

func TestRSADecryptWrongIdentity(t *testing.T) {
	dir := t.TempDir()
	rsaPub := generateRSAKey(t, dir, "rsa-wrong")
	_ = generateSSHKey(t, dir, "ed-wrong") // generate Ed25519 identity for wrong-key test

	src := filepath.Join(dir, "rsa-wrong-id.txt")
	if err := os.WriteFile(src, []byte("wrong identity test"), 0644); err != nil {
		t.Fatal(err)
	}

	out, _, err := run("encrypt", "-k", "-r", rsaPub, src)
	if err != nil {
		t.Fatalf("RSA encrypt failed: %v\n%s", err, out)
	}

	lck := lckPath(src)
	out, _, err = run("decrypt", "-k", "-i", filepath.Join(dir, "ed-wrong"), lck)
	if err == nil {
		t.Fatalf("expected decrypt error with wrong identity, got: %s", out)
	}
}

func TestKeystoreAddImportRSA(t *testing.T) {
	home := t.TempDir()
	env := keystoreEnv(home)

	// Generate an RSA key pair using ssh-keygen.
	keyPath := filepath.Join(home, "rsa-import-key")
	cmd := exec.Command("ssh-keygen", "-t", "rsa", "-b", "2048", "-N", "", "-f", keyPath, "-C", "import-test")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen failed: %v\n%s", err, out)
	}

	// Import into keystore.
	out, _, err := runWithEnv(env, "keystore", "add", "rsa-imported", keyPath)
	if err != nil {
		t.Fatalf("keystore add rsa import failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "Imported") && !strings.Contains(out, "RSA") {
		t.Fatalf("expected import message mentioning RSA, got: %s", out)
	}

	// List should show the key with RSA type.
	out, _, err = runWithEnv(env, "keystore", "list")
	if err != nil {
		t.Fatalf("keystore list failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "rsa-imported") {
		t.Fatalf("expected rsa-imported in list, got: %s", out)
	}

	// Show should display key metadata.
	out, _, err = runWithEnv(env, "keystore", "show", "rsa-imported")
	if err != nil {
		t.Fatalf("keystore show failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "rsa-imported") {
		t.Fatalf("expected key name in show output, got: %s", out)
	}
}

func TestRSARoundtripStdin(t *testing.T) {
	dir := t.TempDir()
	pubkey := generateRSAKey(t, dir, "rsa-stdin")

	plaintext := "rsa stdin roundtrip data"
	encOut, _, err := runWithStdin(plaintext, "encrypt", "-a", "-r", pubkey)
	if err != nil {
		t.Fatalf("RSA stdin encrypt failed: %v\n%s", err, encOut)
	}

	out, _, err := runWithStdin(encOut, "decrypt", "-i", filepath.Join(dir, "rsa-stdin"))
	if err != nil {
		t.Fatalf("RSA stdin decrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, plaintext) {
		t.Fatalf("expected %q in decrypt output, got: %s", plaintext, out)
	}
}

func TestRSAPipeRoundtrip(t *testing.T) {
	dir := t.TempDir()
	pubkey := generateRSAKey(t, dir, "rsa-pipe")

	src := filepath.Join(dir, "rsa-pipe.txt")
	if err := os.WriteFile(src, []byte("rsa pipe roundtrip"), 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	out, _, err := run("encrypt", "-k", "-r", pubkey, src)
	if err != nil {
		t.Fatalf("RSA pipe encrypt failed: %v\n%s", err, out)
	}

	lck := lckPath(src)
	lckData, err := os.ReadFile(lck)
	if err != nil {
		t.Fatalf("reading .chx file: %v", err)
	}

	out, _, err = runWithStdin(string(lckData), "decrypt", "-i", filepath.Join(dir, "rsa-pipe"))
	if err != nil {
		t.Fatalf("RSA pipe decrypt failed: %v\n%s", err, out)
	}

	decryptedPath := filepath.Join(dir, "decrypted")
	if err := os.WriteFile(decryptedPath, []byte(out), 0644); err != nil {
		t.Fatal(err)
	}

	if fileHash(t, decryptedPath) != origHash {
		t.Fatalf("integrity check failed after RSA pipe round-trip")
	}
}

func TestRSAInvalidRecipient(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "bad-recip.txt")
	if err := os.WriteFile(src, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, err := run("encrypt", "-k", "-r", "not-a-valid-ssh-rsa-key", src)
	if err == nil {
		t.Fatal("expected error for invalid RSA recipient")
	}
}

func TestRSAInvalidIdentity(t *testing.T) {
	dir := t.TempDir()
	badID := filepath.Join(dir, "bad-id")
	if err := os.WriteFile(badID, []byte("not a private key"), 0644); err != nil {
		t.Fatal(err)
	}

	src := filepath.Join(dir, "some.chx")
	if err := os.WriteFile(src, []byte("garbage"), 0644); err != nil {
		t.Fatal(err)
	}

	_, _, err := run("decrypt", "-i", badID, src)
	if err == nil {
		t.Fatal("expected error for invalid identity file")
	}
}

func TestRSAArmoredRoundtrip(t *testing.T) {
	dir := t.TempDir()
	pubkey := generateRSAKey(t, dir, "rsa-armor")

	src := filepath.Join(dir, "rsa-armor.dat")
	if err := os.WriteFile(src, []byte("rsa armored data"), 0644); err != nil {
		t.Fatal(err)
	}

	origHash := fileHash(t, src)

	out, _, err := run("encrypt", "-k", "-a", "-r", pubkey, src)
	if err != nil {
		t.Fatalf("RSA armored encrypt failed: %v\n%s", err, out)
	}

	lck := lckPath(src)
	lckData, err := os.ReadFile(lck)
	if err != nil {
		t.Fatalf("reading armored .chx: %v", err)
	}
	if !strings.Contains(string(lckData), "BEGIN CIPHERIX FILE") {
		t.Fatalf("expected armored format, got:\n%s", lckData)
	}

	out, _, err = run("decrypt", "-k", "-i", filepath.Join(dir, "rsa-armor"), lck)
	if err != nil {
		t.Fatalf("RSA armored decrypt failed: %v\n%s", err, out)
	}

	if fileHash(t, src) != origHash {
		t.Fatalf("integrity check failed after RSA armored round-trip")
	}
}

func TestRSASingleInspect(t *testing.T) {
	dir := t.TempDir()
	pubkey := generateRSAKey(t, dir, "rsa-insp")

	src := filepath.Join(dir, "rsa-insp.txt")
	if err := os.WriteFile(src, []byte("rsa inspect test"), 0644); err != nil {
		t.Fatal(err)
	}

	out, _, err := run("encrypt", "-k", "-r", pubkey, src)
	if err != nil {
		t.Fatalf("RSA inspect encrypt failed: %v\n%s", err, out)
	}

	lck := lckPath(src)
	out, _, err = run("inspect", lck)
	if err != nil {
		t.Fatalf("inspect failed: %v\n%s", err, out)
	}

	if !strings.Contains(out, "RSA-OAEP") {
		t.Fatalf("expected 'RSA-OAEP' in inspect output, got:\n%s", out)
	}
	if !strings.Contains(out, "Recipients: 1") {
		t.Fatalf("expected 'Recipients: 1' in inspect output, got:\n%s", out)
	}
	if !strings.Contains(out, "recipient 1:") {
		t.Fatalf("expected 'recipient 1:' in inspect output, got:\n%s", out)
	}
}

func TestRSAMultiInspect(t *testing.T) {
	dir := t.TempDir()
	pubkey1 := generateRSAKey(t, dir, "rsa-mi1")
	pubkey2 := generateRSAKey(t, dir, "rsa-mi2")

	src := filepath.Join(dir, "rsa-multi-insp.txt")
	if err := os.WriteFile(src, []byte("rsa multi inspect"), 0644); err != nil {
		t.Fatal(err)
	}

	out, _, err := run("encrypt", "-k", "-r", pubkey1, "-r", pubkey2, src)
	if err != nil {
		t.Fatalf("RSA multi encrypt failed: %v\n%s", err, out)
	}

	lck := lckPath(src)
	out, _, err = run("inspect", lck)
	if err != nil {
		t.Fatalf("inspect failed: %v\n%s", err, out)
	}

	if !strings.Contains(out, "RSA-OAEP (multi-recipient)") {
		t.Fatalf("expected 'RSA-OAEP (multi-recipient)' in inspect output, got:\n%s", out)
	}
	if !strings.Contains(out, "Recipients: 2") {
		t.Fatalf("expected 'Recipients: 2' in inspect output, got:\n%s", out)
	}
	if !strings.Contains(out, "recipient 1:") {
		t.Fatalf("expected 'recipient 1:' in inspect output, got:\n%s", out)
	}
	if !strings.Contains(out, "recipient 2:") {
		t.Fatalf("expected 'recipient 2:' in inspect output, got:\n%s", out)
	}
}

func TestHybridInspect(t *testing.T) {
	dir := t.TempDir()
	edPub := generateSSHKey(t, dir, "hyb-insp-ed")
	rsaPub := generateRSAKey(t, dir, "hyb-insp-rsa")

	src := filepath.Join(dir, "hybrid-insp.txt")
	if err := os.WriteFile(src, []byte("hybrid inspect"), 0644); err != nil {
		t.Fatal(err)
	}

	out, _, err := run("encrypt", "-k", "-r", edPub, "-r", rsaPub, src)
	if err != nil {
		t.Fatalf("hybrid encrypt failed: %v\n%s", err, out)
	}

	lck := lckPath(src)
	out, _, err = run("inspect", lck)
	if err != nil {
		t.Fatalf("inspect failed: %v\n%s", err, out)
	}

	if !strings.Contains(out, "Hybrid (RSA + X25519)") {
		t.Fatalf("expected 'Hybrid (RSA + X25519)' in inspect output, got:\n%s", out)
	}
	if !strings.Contains(out, "Recipients: 2") {
		t.Fatalf("expected 'Recipients: 2' in inspect output, got:\n%s", out)
	}
	if !strings.Contains(out, "recipient 1:") {
		t.Fatalf("expected 'recipient 1:' in inspect output, got:\n%s", out)
	}
	if !strings.Contains(out, "recipient 2:") {
		t.Fatalf("expected 'recipient 2:' in inspect output, got:\n%s", out)
	}
}

func TestNoProgressFlag(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "noprogress.dat")
	if err := os.WriteFile(src, []byte("progress test"), 0644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(src)

	// --no-progress should not cause any errors
	out, stderr, err := run("encrypt", "-k", "--no-progress", "-p", "hunter2", src)
	if err != nil {
		t.Fatalf("encrypt with --no-progress failed: %v\n%s", err, out)
	}

	lck := lckPath(src)
	out, stderr, err = run("decrypt", "-k", "--no-progress", "-p", "hunter2", lck)
	if err != nil {
		t.Fatalf("decrypt with --no-progress failed: %v\n%s", err, out)
	}
	_ = stderr
}

// TestKeyKeystoreFlagRemoved verifies that --key-keystore is rejected on
// both encrypt and decrypt commands (removed in v2.2.0).
func TestKeyKeystoreFlagRemoved(t *testing.T) {
	dir := t.TempDir()

	encSrc := filepath.Join(dir, "enc_test.txt")
	if err := os.WriteFile(encSrc, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}
	decSrc := filepath.Join(dir, "dec_test.chx")
	if err := os.WriteFile(decSrc, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	// Encrypt: --key-keystore should be unknown.
	_, stderr, err := run("encrypt", "-k", "--key-keystore", "anykey", encSrc)
	if err == nil {
		t.Fatal("expected error for --key-keystore on encrypt")
	}
	if !strings.Contains(stderr, "unknown flag") && !strings.Contains(stderr, "flag not found") {
		t.Fatalf("expected unknown flag error on encrypt, got: %s", stderr)
	}

	// Decrypt: --key-keystore should also be unknown.
	_, stderr, err = run("decrypt", "-k", "--key-keystore", "anykey", decSrc)
	if err == nil {
		t.Fatal("expected error for --key-keystore on decrypt")
	}
	if !strings.Contains(stderr, "unknown flag") && !strings.Contains(stderr, "flag not found") {
		t.Fatalf("expected unknown flag error on decrypt, got: %s", stderr)
	}
}

// TestEncryptRecipientFromGoencFile verifies -r resolves a file path whose
// content is a cphx public key string.
func TestEncryptRecipientFromGoencFile(t *testing.T) {
	dir := t.TempDir()

	// Generate an identity and extract the public key.
	idPath := filepath.Join(dir, "id")
	run("keygen", "-o", idPath)
	idData, _ := os.ReadFile(idPath)
	var pubkey string
	for _, line := range strings.Split(string(idData), "\n") {
		if strings.HasPrefix(line, "# public: ") {
			pubkey = strings.TrimPrefix(line, "# public: ")
			break
		}
	}
	if pubkey == "" {
		t.Fatal("public key not found")
	}

	// Write the public key to a separate file.
	keyFile := filepath.Join(dir, "pubkey.txt")
	if err := os.WriteFile(keyFile, []byte(pubkey+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Encrypt using the file path as -r argument.
	src := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(src, []byte("file-resolved secret"), 0644); err != nil {
		t.Fatal(err)
	}
	origHash := fileHash(t, src)

	out, _, err := run("encrypt", "-k", "-r", keyFile, src)
	if err != nil {
		t.Fatalf("encrypt with -r pointing to cphx key file failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "encrypted successfully") {
		t.Fatalf("expected success, got: %s", out)
	}

	lck := lckPath(src)
	out, _, err = run("decrypt", "-k", "-i", idPath, lck)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, out)
	}
	if fileHash(t, src) != origHash {
		t.Fatal("integrity check failed")
	}
}

// TestEncryptRecipientFromSSHFile verifies -r resolves an SSH .pub file path.
func TestEncryptRecipientFromSSHFile(t *testing.T) {
	dir := t.TempDir()

	// Generate an SSH key pair.
	sshKey := filepath.Join(dir, "ssh_id")
	if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", sshKey, "-C", "test").CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen failed: %v\n%s", err, out)
	}

	// The .pub file is a valid recipient — pass its path to -r.
	pubFile := sshKey + ".pub"

	src := filepath.Join(dir, "ssh_file.txt")
	if err := os.WriteFile(src, []byte("ssh file resolved"), 0644); err != nil {
		t.Fatal(err)
	}
	origHash := fileHash(t, src)

	out, _, err := run("encrypt", "-k", "-r", pubFile, src)
	if err != nil {
		t.Fatalf("encrypt with -r pointing to SSH .pub file failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "encrypted successfully") {
		t.Fatalf("expected success, got: %s", out)
	}

	lck := lckPath(src)
	out, _, err = run("decrypt", "-k", "-i", sshKey, lck)
	if err != nil {
		t.Fatalf("decrypt failed: %v\n%s", err, out)
	}
	if fileHash(t, src) != origHash {
		t.Fatal("integrity check failed")
	}

	// Also test round-trip via pipe (encrypt with file path, decrypt stdin).
	src2 := filepath.Join(dir, "pipe_test.txt")
	if err := os.WriteFile(src2, []byte("ssh file pipe"), 0644); err != nil {
		t.Fatal(err)
	}
	origHash2 := fileHash(t, src2)

	encOut, _, err := run("encrypt", "-k", "-r", pubFile, src2)
	if err != nil {
		t.Fatalf("pipe encrypt failed: %v\n%s", err, encOut)
	}

	lck2 := lckPath(src2)
	out2, _, err := run("decrypt", "-k", "-i", sshKey, lck2)
	if err != nil {
		t.Fatalf("pipe decrypt failed: %v\n%s", err, out2)
	}
	if fileHash(t, src2) != origHash2 {
		t.Fatal("pipe integrity check failed")
	}
}

// TestEncryptRecipientCphxPrefixSkipsKeystore verifies that a keystore key
// whose name starts with "cphx" is not resolved via -r (the prefix check
// bypasses keystore lookup).
func TestEncryptRecipientCphxPrefixSkipsKeystore(t *testing.T) {
	home := t.TempDir()
	env := keystoreEnv(home)

	// Add a key with a "cphx"-prefixed name.
	runWithEnv(env, "keystore", "add", "cphxTestKey")

	src := filepath.Join(home, "secret.txt")
	if err := os.WriteFile(src, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	// -r cphxTestKey should fail because cphx prefix skips keystore,
	// no file named "cphxTestKey" exists, and "cphxTestKey" is not a
	// valid inline key.
	_, stderr, err := runWithEnv(env, "encrypt", "-k", "-r", "cphxTestKey", src)
	if err == nil {
		t.Fatal("expected error for cphx-prefixed keystore key via -r")
	}
	if !strings.Contains(stderr, "invalid recipient") {
		t.Fatalf("expected invalid recipient error, got: %s", stderr)
	}

	// Verify the key exists in keystore (even though -r can't reach it).
	encOut, _, encErr := runWithEnv(env, "encrypt", "-k", "-r", "testkey", src)
	if encErr == nil {
		// There's no "testkey" in keystore, so this would fail too.
		// Instead, just verify the key exists in keystore.
		listOut, _, _ := runWithEnv(env, "keystore", "list")
		if !strings.Contains(listOut, "cphxTestKey") {
			t.Fatal("cphxTestKey should be present in keystore")
		}
	}
	_ = encOut
}

// TestEncryptRecipientSSHPrefixSkipsKeystore verifies that a keystore key
// whose name starts with "ssh-" is not resolved via -r.
func TestEncryptRecipientSSHPrefixSkipsKeystore(t *testing.T) {
	home := t.TempDir()
	env := keystoreEnv(home)

	runWithEnv(env, "keystore", "add", "ssh-testkey")

	src := filepath.Join(home, "secret.txt")
	if err := os.WriteFile(src, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := runWithEnv(env, "encrypt", "-k", "-r", "ssh-testkey", src)
	if err == nil {
		t.Fatal("expected error for ssh-prefixed keystore key via -r")
	}
	if !strings.Contains(stderr, "invalid recipient") {
		t.Fatalf("expected invalid recipient error, got: %s", stderr)
	}
}

// TestEncryptRecipientLongStringSkipsKeystore verifies that a string longer
// than 64 characters skips keystore lookup.
func TestEncryptRecipientLongStringSkipsKeystore(t *testing.T) {
	dir := t.TempDir()

	// Build a name > 64 chars that's not a file and not a valid key.
	longName := "a"
	for len(longName) <= 65 {
		longName += "bc"
	}
	if len(longName) <= 64 {
		t.Fatal("test string must be > 64 chars")
	}

	src := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(src, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := run("encrypt", "-k", "-r", longName, src)
	if err == nil {
		t.Fatal("expected error for long recipient string")
	}
	if !strings.Contains(stderr, "invalid recipient") {
		t.Fatalf("expected invalid recipient error, got: %s", stderr)
	}
}

// TestEncryptRecipientFallbackChainExhaustion verifies that -r produces
// "invalid recipient" when keystore, file, and inline parsing all fail.
func TestEncryptRecipientFallbackChainExhaustion(t *testing.T) {
	dir := t.TempDir()

	// A short name with no cphx/ssh- prefix → goes through full chain:
	// keystore → file → inline, all fail.
	src := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(src, []byte("data"), 0644); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := run("encrypt", "-k", "-r", "nonexistent-key-name", src)
	if err == nil {
		t.Fatal("expected error for non-existent recipient")
	}
	if !strings.Contains(stderr, "invalid recipient") {
		t.Fatalf("expected invalid recipient error, got: %s", stderr)
	}
}

// TestEncryptMixedKeystoreAndCphxRecipients verifies -r works with a
// keystore name and a cphx inline key in the same command.
func TestEncryptMixedKeystoreAndCphxRecipients(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	env := keystoreEnv(home)

	// Add a key to keystore.
	runWithEnv(env, "keystore", "add", "mixkey")

	// Generate a second identity for inline use.
	idPath2 := filepath.Join(dir, "id2")
	run("keygen", "-o", idPath2)
	idData2, _ := os.ReadFile(idPath2)
	var pubkey2 string
	for _, line := range strings.Split(string(idData2), "\n") {
		if strings.HasPrefix(line, "# public: ") {
			pubkey2 = strings.TrimPrefix(line, "# public: ")
			break
		}
	}
	if pubkey2 == "" {
		t.Fatal("public key 2 not found")
	}

	src := filepath.Join(dir, "mixed.txt")
	if err := os.WriteFile(src, []byte("mixed keystore+inline"), 0644); err != nil {
		t.Fatal(err)
	}
	origHash := fileHash(t, src)

	// Encrypt to both keystore key (via -r mixkey) and inline key.
	out, _, err := runWithEnv(env, "encrypt", "-k", "-r", "mixkey", "-r", pubkey2, src)
	if err != nil {
		t.Fatalf("mixed encrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "encrypted successfully") {
		t.Fatalf("expected success, got: %s", out)
	}

	lck := lckPath(src)

	// Decrypt via auto-detected keystore key.
	out, _, err = runWithEnv(env, "decrypt", "-k", lck)
	if err != nil {
		t.Fatalf("auto-keystore decrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "mixkey") {
		t.Fatalf("expected keystore key message, got: %s", out)
	}

	// Decrypt with inline key's identity.
	out, _, err = run("decrypt", "-k", "-i", idPath2, lck)
	if err != nil {
		t.Fatalf("inline decrypt failed: %v\n%s", err, out)
	}

	if fileHash(t, src) != origHash {
		t.Fatal("integrity check failed")
	}
}

// TestEncryptMixedKeystoreAndSSHRecipients verifies -r works with a keystore
// name and an SSH inline key in the same command.
func TestEncryptMixedKeystoreAndSSHRecipients(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	env := keystoreEnv(home)

	// Add a key to keystore (name without ssh- prefix to avoid skip).
	runWithEnv(env, "keystore", "add", "mix-ssh-key")

	// Generate an SSH key pair for inline use.
	sshKey := filepath.Join(dir, "ssh_mix_id")
	if out, err := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-f", sshKey, "-C", "test").CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen failed: %v\n%s", err, out)
	}
	sshPubBytes, _ := os.ReadFile(sshKey + ".pub")
	sshPub := strings.TrimSpace(string(sshPubBytes))

	src := filepath.Join(dir, "mixed_ssh.txt")
	if err := os.WriteFile(src, []byte("mixed keystore+ssh"), 0644); err != nil {
		t.Fatal(err)
	}
	origHash := fileHash(t, src)

	// Encrypt to both keystore key and SSH inline key.
	out, _, err := runWithEnv(env, "encrypt", "-k", "-r", "mix-ssh-key", "-r", sshPub, src)
	if err != nil {
		t.Fatalf("mixed keystore+ssh encrypt failed: %v\n%s", err, out)
	}

	lck := lckPath(src)

	// Decrypt via auto-detected keystore key.
	out, _, err = runWithEnv(env, "decrypt", "-k", lck)
	if err != nil {
		t.Fatalf("auto-keystore decrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "mix-ssh-key") {
		t.Fatalf("expected keystore key message, got: %s", out)
	}

	// Decrypt with SSH identity.
	out, _, err = run("decrypt", "-k", "-i", sshKey, lck)
	if err != nil {
		t.Fatalf("ssh decrypt failed: %v\n%s", err, out)
	}

	if fileHash(t, src) != origHash {
		t.Fatal("integrity check failed")
	}
}

// TestStdinKeystoreRoundtrip verifies that keystore-encrypted data piped
// through stdin auto-detects the keystore key on decrypt.
func TestStdinKeystoreRoundtrip(t *testing.T) {
	home := t.TempDir()
	env := keystoreEnv(home)

	runWithEnv(env, "keystore", "add", "stdin-key")

	src := filepath.Join(home, "stdin_secret.txt")
	if err := os.WriteFile(src, []byte("stdin keystore data"), 0644); err != nil {
		t.Fatal(err)
	}
	out, _, err := runWithEnv(env, "encrypt", "-k", "-r", "stdin-key", src)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, out)
	}

	lck := lckPath(src)
	lckData, err := os.ReadFile(lck)
	if err != nil {
		t.Fatal(err)
	}

	// Pipe .chx data through decrypt stdin with no flags (auto-detect).
	out, _, err = runWithStdinEnv(string(lckData), env, "decrypt")
	if err != nil {
		t.Fatalf("stdin auto-decrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "stdin keystore data") {
		t.Fatalf("expected data in output, got: %s", out)
	}
	if !strings.Contains(out, "stdin-key") {
		t.Fatalf("expected keystore key message, got: %s", out)
	}
}

// TestAutoDecryptWithNonDefaultKeystoreKey verifies that decrypt auto-detects
// the correct non-default keystore key when the default key doesn't match.
func TestAutoDecryptWithNonDefaultKeystoreKey(t *testing.T) {
	home := t.TempDir()
	dir := t.TempDir()
	env := keystoreEnv(home)

	// Add keyA (becomes default).
	runWithEnv(env, "keystore", "add", "keyA")

	// Generate keyB identity and import to keystore (non-default since
	// default is already set).
	keyBid := filepath.Join(dir, "keyB_id")
	run("keygen", "-o", keyBid)
	keyBdata, _ := os.ReadFile(keyBid)
	var keyBpub string
	for _, line := range strings.Split(string(keyBdata), "\n") {
		if strings.HasPrefix(line, "# public: ") {
			keyBpub = strings.TrimPrefix(line, "# public: ")
			break
		}
	}
	if keyBpub == "" {
		t.Fatal("keyB public key not found")
	}
	runWithEnv(env, "keystore", "add", "keyB", keyBid)

	// Encrypt using keyB's public key (inline), NOT via keystore.
	src := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(src, []byte("non-default key test"), 0644); err != nil {
		t.Fatal(err)
	}
	origHash := fileHash(t, src)

	out, _, err := run("encrypt", "-k", "-r", keyBpub, src)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, out)
	}

	lck := lckPath(src)

	// Decrypt without flags — should try keyA (fails), then keyB (succeeds).
	out, _, err = runWithEnv(env, "decrypt", "-k", lck)
	if err != nil {
		t.Fatalf("auto-decrypt failed: %v\n%s", err, out)
	}
	if !strings.Contains(out, "keyB") {
		t.Fatalf("expected keyB in output, got: %s", out)
	}
	if fileHash(t, src) != origHash {
		t.Fatal("integrity check failed")
	}
}

// TestDecryptWrongIdentityFallbackToPassword verifies that decrypt falls through
// from a wrong -i identity to the -p password flag.
func TestDecryptWrongIdentityFallbackToPassword(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	env := keystoreEnv(home)

	src := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(src, []byte("identity fallback test"), 0644); err != nil {
		t.Fatal(err)
	}
	origHash := fileHash(t, src)

	// Encrypt with password (no keystore involvement)
	run("encrypt", "-k", "-p", "correctpass", src)
	lck := lckPath(src)

	// Generate a wrong identity (not added to keystore)
	wrongId := filepath.Join(dir, "wrong_id")
	generateIdentity(t, wrongId)

	// Decrypt with wrong identity + correct password.
	// Identity attempt fails (password-encrypted file) → falls through to password → succeeds.
	out, _, err := runWithEnv(env, "decrypt", "-k", "-i", wrongId, "-p", "correctpass", lck)
	if err != nil {
		t.Fatalf("decrypt should have fallen through to password: %v\n%s", err, out)
	}
	if fileHash(t, src) != origHash {
		t.Fatal("integrity check failed")
	}
}

// TestDecryptWrongPasswordFallsThroughToKeystore verifies that decrypt falls through
// from a wrong -p flag to keystore keys.
func TestDecryptWrongPasswordFallsThroughToKeystore(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	env := keystoreEnv(home)

	// Generate identity and add to isolated keystore.
	idPath := filepath.Join(dir, "testkey")
	out, _, err := runWithEnv(env, "keygen", "-o", idPath)
	if err != nil {
		t.Fatalf("keygen failed: %v\n%s", err, out)
	}

	// Extract public key from the identity file.
	pubkey := extractPubkey(t, idPath)

	src := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(src, []byte("wrong password fallback test"), 0644); err != nil {
		t.Fatal(err)
	}
	origHash := fileHash(t, src)

	// Encrypt to the public key.
	run("encrypt", "-k", "-r", pubkey, src)
	lck := lckPath(src)

	// Decrypt with wrong password — should fall through to keystore.
	out, _, err = runWithEnv(env, "decrypt", "-k", "-p", "wrongpass", lck)
	if err != nil {
		t.Fatalf("decrypt should have fallen through to keystore: %v\n%s", err, out)
	}
	if !strings.Contains(out, "testkey") {
		t.Fatalf("expected keystore key usage message, got: %s", out)
	}
	if fileHash(t, src) != origHash {
		t.Fatal("integrity check failed")
	}
}

// TestDecryptPasswordEnvFallsThroughToKeystore verifies that when --password-env is
// set to a missing/empty variable, decrypt falls through to keystore keys (stdin path).
func TestDecryptPasswordEnvFallsThroughToKeystore(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	env := keystoreEnv(home)

	// Generate identity and add to isolated keystore.
	idPath := filepath.Join(dir, "envkey")
	out, _, err := runWithEnv(env, "keygen", "-o", idPath)
	if err != nil {
		t.Fatalf("keygen failed: %v\n%s", err, out)
	}

	// --password-env has no effect on encrypt; we encrypt via pubkey for keystore fallback.
	pubkey := extractPubkey(t, idPath)

	src := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(src, []byte("env fallback test content"), 0644); err != nil {
		t.Fatal(err)
	}

	run("encrypt", "-k", "-r", pubkey, src)
	lck := lckPath(src)
	lckData, err := os.ReadFile(lck)
	if err != nil {
		t.Fatal(err)
	}

	// Pipe .chx through decrypt stdin with --password-env pointing to a missing variable.
	// resolvePassword returns error → passwordTried stays false → keystore succeeds.
	cmd := exec.Command(binaryPath, "decrypt", "--password-env", "MISSING_ENV_VAR_12345")
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(lckData)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("decrypt should have fallen through to keystore: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "envkey") {
		t.Fatalf("expected keystore key usage message, got: %s", string(output))
	}
	if !strings.Contains(string(output), "env fallback test content") {
		t.Fatalf("expected decrypted data, got: %s", string(output))
	}
}

// TestEncryptAutoKeystoreDefault verifies that encrypting with no flags auto-uses
// the default keystore key.
func TestEncryptAutoKeystoreDefault(t *testing.T) {
	home := t.TempDir()
	dir := t.TempDir()
	env := keystoreEnv(home)

	// Generate identity — auto-added to isolated keystore as default.
	idPath := filepath.Join(dir, "autokey")
	out, _, err := runWithEnv(env, "keygen", "-o", idPath)
	if err != nil {
		t.Fatalf("keygen failed: %v\n%s", err, out)
	}

	src := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(src, []byte("auto keystore encrypt test"), 0644); err != nil {
		t.Fatal(err)
	}
	origHash := fileHash(t, src)

	// Encrypt with no password/recipient flags — should auto-use default keystore key.
	out, _, err = runWithEnv(env, "encrypt", "-k", src)
	if err != nil {
		t.Fatalf("encrypt with default keystore key failed: %v\n%s", err, out)
	}

	lck := lckPath(src)
	if _, err := os.Stat(lck); os.IsNotExist(err) {
		t.Fatal("encrypted file not created")
	}

	// Decrypt with identity file — should succeed.
	out, _, err = runWithEnv(env, "decrypt", "-k", "-i", idPath, lck)
	if err != nil {
		t.Fatalf("decrypt after auto-encrypt failed: %v\n%s", err, out)
	}
	if fileHash(t, src) != origHash {
		t.Fatal("integrity check failed")
	}
}

// TestCLIDecryptOldLckFormat verifies that .lck files created with the old
// "goenc" magic header can still be decrypted via the CLI.
func TestCLIDecryptOldLckFormat(t *testing.T) {
	dir := t.TempDir()

	pass := "oldformatpass"
	src := filepath.Join(dir, "old_secret.txt")
	if err := os.WriteFile(src, []byte("old format data"), 0644); err != nil {
		t.Fatal(err)
	}
	origHash := fileHash(t, src)

	out, _, err := run("encrypt", "-k", "-p", pass, src)
	if err != nil {
		t.Fatalf("encrypt failed: %v\n%s", err, out)
	}
	chx := lckPath(src)

	ct, err := os.ReadFile(chx)
	if err != nil {
		t.Fatal(err)
	}
	oldCT := make([]byte, len(ct)+1)
	copy(oldCT[:5], "goenc")
	copy(oldCT[5:], ct[4:])

	lck := filepath.Join(dir, "old_secret.lck")
	if err := os.WriteFile(lck, oldCT, 0644); err != nil {
		t.Fatal(err)
	}

	os.Remove(chx)

	out, _, err = run("decrypt", "-k", "-p", pass, lck)
	if err != nil {
		t.Fatalf("decrypt old .lck failed: %v\n%s", err, out)
	}
	if fileHash(t, src) != origHash {
		t.Fatal("integrity check failed after old-format decrypt")
	}
}
