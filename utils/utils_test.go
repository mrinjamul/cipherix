package utils

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestGetVersion(t *testing.T) {
	out := GetVersion()
	if out == "" || len(out) == 0 {
		t.Errorf("Want strings but got nil")
	}
}

func TestGetFileNameExt(t *testing.T) {
	testcases := []struct {
		name         string
		fullFileName string
		filename     string
		extension    string
	}{
		{"File with Extension", "test.jpg", "test", "jpg"},
		{"File without Extension", "test", "test", ""},
		{"File with 2 latter Extension", "test.md", "test", "md"},
		{"File name smaller than 4", "xyz", "xyz", ""},
	}

	for _, testcase := range testcases {
		t.Run(testcase.name, func(t *testing.T) {
			fileName, ext := GetFileNameExt(testcase.fullFileName)
			if fileName != testcase.filename || ext != testcase.extension {
				t.Errorf("%v should be '%v' with '%v'; but got '%v' with '%v'",
					testcase.fullFileName, testcase.filename,
					testcase.extension, fileName, ext)
			}
		})
	}
}

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(path, []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	data, err := ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("got %q, want %q", string(data), "hello")
	}

	_, err = ReadFile(filepath.Join(dir, "nonexistent"))
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestSaveFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "output.bin")
	if err := SaveFile(path, []byte("saved data")); err != nil {
		t.Fatalf("SaveFile failed: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "saved data" {
		t.Fatalf("got %q, want %q", string(data), "saved data")
	}
}

func TestIsDir(t *testing.T) {
	dir := t.TempDir()
	filePath := filepath.Join(dir, "afile")
	if err := os.WriteFile(filePath, []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}

	isDir, err := IsDir(dir)
	if err != nil {
		t.Fatalf("IsDir on dir failed: %v", err)
	}
	if !isDir {
		t.Fatal("expected true for directory")
	}

	isDir, err = IsDir(filePath)
	if err != nil {
		t.Fatalf("IsDir on file failed: %v", err)
	}
	if isDir {
		t.Fatal("expected false for file")
	}

	_, err = IsDir(filepath.Join(dir, "nonexistent"))
	if err == nil {
		t.Fatal("expected error for nonexistent path")
	}
}

func TestPasswordEntropy(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantLow  float64
		wantHigh float64
	}{
		{"only digits", "1234", 13.0, 14.0},
		{"only lowercase", "abcdefgh", 37.0, 38.0},
		{"lowercase long", "abcdefghijklmnop", 75.0, 76.0},
		{"mixed case digits", "Abcd1234", 47.0, 48.0},
		{"all types", "CorrectHorseBatteryStaple!", 166.0, 167.0},
		{"empty", "", 0, 0},
		{"single char", "a", 4.0, 5.0},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := PasswordEntropy([]byte(tc.password))
			if got < tc.wantLow || got > tc.wantHigh {
				t.Errorf("PasswordEntropy(%q) = %.2f, want between %.2f and %.2f",
					tc.password, got, tc.wantLow, tc.wantHigh)
			}
		})
	}
}

func TestErrorLogger(t *testing.T) {
	ErrorLogger(nil)
	ErrorLogger(os.ErrNotExist)
}

func TestSaveFileReadOnlyParent(t *testing.T) {
	dir := t.TempDir()
	readonlyDir := filepath.Join(dir, "readonly")
	if err := os.MkdirAll(readonlyDir, 0444); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(readonlyDir, "test.bin")
	err := SaveFile(path, []byte("data"))
	if err == nil {
		t.Fatal("expected error writing to read-only directory")
	}
}

func TestGetFileNameExtMultiDot(t *testing.T) {
	tests := []struct {
		name     string
		full     string
		wantFile string
		wantExt  string
	}{
		{"tar.gz", "archive.tar.gz", "archive.tar", "gz"},
		{"a.b.c", "a.b.c.txt", "a.b.c", "txt"},
		{"hidden", ".gitignore", ".gitignore", ""},
		{"hidden with ext", ".config.json", ".config.json", ""}, // custom GetFileNameExt only handles 2/3-char ext
		{"no ext", "Makefile", "Makefile", ""},
		{"just dot", ".", ".", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			file, ext := GetFileNameExt(tc.full)
			if file != tc.wantFile || ext != tc.wantExt {
				t.Errorf("GetFileNameExt(%q) = (%q, %q), want (%q, %q)",
					tc.full, file, ext, tc.wantFile, tc.wantExt)
			}
		})
	}
}

func TestPasswordEntropyUnicode(t *testing.T) {
	entropy := PasswordEntropy([]byte("パスワード123!@#"))
	if entropy <= 0 {
		t.Fatal("expected positive entropy for Unicode password")
	}
}

func TestArmorEncodeDecode(t *testing.T) {
	original := []byte("hello armor test data 123!@#")
	encoded := ArmorEncode(original)

	if !strings.HasPrefix(string(encoded), armorHeader) {
		t.Fatalf("expected armor header, got: %s", string(encoded[:len(armorHeader)]))
	}
	if !strings.HasSuffix(strings.TrimSpace(string(encoded)), armorFooter) {
		t.Fatalf("expected armor footer suffix, got: %s", string(encoded[len(encoded)-len(armorFooter)-5:]))
	}

	decoded, err := ArmorDecode(encoded)
	if err != nil {
		t.Fatalf("ArmorDecode failed: %v", err)
	}
	if !bytes.Equal(decoded, original) {
		t.Fatalf("decode mismatch: got %q, want %q", string(decoded), string(original))
	}
}

func TestArmorDecodeNotArmored(t *testing.T) {
	_, err := ArmorDecode([]byte("not armored data"))
	if err == nil {
		t.Fatal("expected error for non-armored data")
	}
}

func TestArmorDecodeCorrupted(t *testing.T) {
	original := []byte("corrupt this")
	encoded := ArmorEncode(original)
	// Corrupt the base64 body: flip a bit in the second line
	lines := strings.Split(string(encoded), "\n")
	if len(lines) < 4 {
		t.Fatal("armor is too short to corrupt")
	}
	// Corrupt a base64 line (including possible trailing whitespace)
	corruptedLine := []byte(lines[2])
	if len(corruptedLine) > 0 {
		corruptedLine[len(corruptedLine)/2] ^= 0xff
	}
	lines[2] = string(corruptedLine)
	corrupted := []byte(strings.Join(lines, "\n"))
	_, err := ArmorDecode(corrupted)
	if err == nil {
		t.Fatal("expected error for corrupted armor data")
	}
}

func TestIsArmored(t *testing.T) {
	if IsArmored([]byte("raw data")) {
		t.Fatal("expected false for non-armored data")
	}
	armored := ArmorEncode([]byte("test"))
	if !IsArmored(armored) {
		t.Fatal("expected true for armored data")
	}
	if !IsArmored([]byte(armorHeader)) {
		t.Fatal("expected true since data starts with armor header")
	}
}

func TestArmorEncodeDecodeEmpty(t *testing.T) {
	encoded := ArmorEncode([]byte{})
	decoded, err := ArmorDecode(encoded)
	if err != nil {
		t.Fatalf("empty decode failed: %v", err)
	}
	if len(decoded) != 0 {
		t.Fatalf("expected empty result, got %d bytes", len(decoded))
	}
}

func TestArmorDecodeMissingFooter(t *testing.T) {
	encoded := ArmorEncode([]byte("data"))
	noFooter := encoded[:len(encoded)-len(armorFooter)]
	_, err := ArmorDecode(noFooter)
	if err == nil {
		t.Fatal("expected error for missing footer")
	}
}

func TestArmorLineWrapping(t *testing.T) {
	// Large data to produce multi-line base64
	data := make([]byte, 200)
	for i := range data {
		data[i] = byte(i)
	}
	encoded := ArmorEncode(data)
	lines := strings.Split(strings.TrimSpace(string(encoded)), "\n")
	// First line is header, then blank, then base64 lines, then footer
	for _, line := range lines[2 : len(lines)-1] {
		if len(line) > armorLineLen {
			t.Fatalf("line exceeds %d chars: %d chars in %q", armorLineLen, len(line), line)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		input int64
		want  string
	}{
		{0, "0 B"},
		{100, "100 B"},
		{1023, "1023 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1048576, "1.0 MiB"},
		{1572864, "1.5 MiB"},
		{1073741824, "1.0 GiB"},
		{1610612736, "1.5 GiB"},
	}
	for _, tc := range tests {
		got := FormatBytes(tc.input)
		if got != tc.want {
			t.Errorf("FormatBytes(%d) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestProgressBarDisabledNonTTY(t *testing.T) {
	// Not running in a terminal, so bar should be disabled for small and large files.
	pb := NewProgressBar(100, "test")
	if pb.enabled {
		t.Fatal("expected progress bar to be disabled in non-TTY environment")
	}
	pb.Add(50)
	// Should not panic or write anything
	pb.Done()
}

func TestProgressBarSmallFile(t *testing.T) {
	// Files under 10MB should be disabled regardless.
	pb := NewProgressBar(1024, "small")
	if pb.enabled {
		t.Fatal("expected progress bar disabled for files under 10MB")
	}
}

func TestProgressReader(t *testing.T) {
	input := make([]byte, 100*1024) // 100 KiB
	for i := range input {
		input[i] = byte(i % 256)
	}
	r := NewProgressReader(bytes.NewReader(input), int64(len(input)), "test", true)
	output, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("ReadAll failed: %v", err)
	}
	r.Done()
	if !bytes.Equal(output, input) {
		t.Fatal("ProgressReader produced different output")
	}
}
