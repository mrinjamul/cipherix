package tar

import (
	"bytes"
	archiveTar "archive/tar"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateExtractFileRoundtrip(t *testing.T) {
	dir := t.TempDir()

	srcFile := filepath.Join(dir, "test.txt")
	if err := os.WriteFile(srcFile, []byte("hello tar"), 0644); err != nil {
		t.Fatal(err)
	}

	tarPath := filepath.Join(dir, "output.tar")
	if err := CreateFile(tarPath, []string{srcFile}, nil); err != nil {
		t.Fatal(err)
	}

	if _, err := os.Stat(tarPath); os.IsNotExist(err) {
		t.Fatal("tar file was not created")
	}

	extractDir := filepath.Join(dir, "extracted")
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := ExtractFile(extractDir, tarPath, nil); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(extractDir, "test.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "hello tar" {
		t.Fatalf("got %q, want %q", string(data), "hello tar")
	}
}

func TestCreateExtractStreamRoundtrip(t *testing.T) {
	dir := t.TempDir()

	srcFile := filepath.Join(dir, "stream.txt")
	if err := os.WriteFile(srcFile, []byte("streaming test"), 0644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := Create(&buf, []string{srcFile}, nil); err != nil {
		t.Fatal(err)
	}

	if buf.Len() == 0 {
		t.Fatal("streaming create produced empty output")
	}

	extractDir := filepath.Join(dir, "streamed")
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := Extract(extractDir, &buf, nil); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(extractDir, "stream.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "streaming test" {
		t.Fatalf("got %q, want %q", string(data), "streaming test")
	}
}

func TestCreateExtractDirectory(t *testing.T) {
	dir := t.TempDir()

	os.MkdirAll(filepath.Join(dir, "mydir", "sub"), 0755)
	if err := os.WriteFile(filepath.Join(dir, "mydir", "file1.txt"), []byte("file1"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "mydir", "sub", "file2.txt"), []byte("file2"), 0644); err != nil {
		t.Fatal(err)
	}

	tarPath := filepath.Join(dir, "dir.tar")
	if err := CreateFile(tarPath, []string{filepath.Join(dir, "mydir")}, nil); err != nil {
		t.Fatal(err)
	}

	extractDir := filepath.Join(dir, "restored")
	if err := os.MkdirAll(extractDir, 0755); err != nil {
		t.Fatal(err)
	}

	if err := ExtractFile(extractDir, tarPath, nil); err != nil {
		t.Fatal(err)
	}

	checkFile := func(path, want string) {
		data, err := os.ReadFile(filepath.Join(extractDir, path))
		if err != nil {
			t.Fatal(err)
		}
		if string(data) != want {
			t.Fatalf("%s: got %q, want %q", path, string(data), want)
		}
	}
	checkFile("mydir/file1.txt", "file1")
	checkFile("mydir/sub/file2.txt", "file2")
}

func TestMultipleFiles(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("aaa"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.txt"), []byte("bbb"), 0644); err != nil {
		t.Fatal(err)
	}

	tarPath := filepath.Join(dir, "multi.tar")
	if err := CreateFile(tarPath, []string{
		filepath.Join(dir, "a.txt"),
		filepath.Join(dir, "b.txt"),
	}, nil); err != nil {
		t.Fatal(err)
	}

	extractDir := filepath.Join(dir, "out")
	os.MkdirAll(extractDir, 0755)
	if err := ExtractFile(extractDir, tarPath, nil); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(filepath.Join(extractDir, "a.txt"))
	if string(data) != "aaa" {
		t.Fatalf("a.txt: got %q", string(data))
	}
	data, _ = os.ReadFile(filepath.Join(extractDir, "b.txt"))
	if string(data) != "bbb" {
		t.Fatalf("b.txt: got %q", string(data))
	}
}

func TestGzipCompression(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "compress.txt"), []byte("compressed data"), 0644); err != nil {
		t.Fatal(err)
	}

	opts := &Options{Compression: GzipCompression}

	tarPath := filepath.Join(dir, "output.tar.gz")
	if err := CreateFile(tarPath, []string{filepath.Join(dir, "compress.txt")}, opts); err != nil {
		t.Fatal(err)
	}

	extractDir := filepath.Join(dir, "extracted")
	os.MkdirAll(extractDir, 0755)
	if err := ExtractFile(extractDir, tarPath, opts); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(filepath.Join(extractDir, "compress.txt"))
	if string(data) != "compressed data" {
		t.Fatalf("got %q", string(data))
	}
}

func TestPathTraversalProtection(t *testing.T) {
	dir := t.TempDir()

	tarPath := filepath.Join(dir, "bad.tar")
	f, err := os.Create(tarPath)
	if err != nil {
		t.Fatal(err)
	}

	atw := archiveTar.NewWriter(f)
	hdr := &archiveTar.Header{
		Name:     "../../../etc/pwned",
		Size:     4,
		Mode:     0644,
		Typeflag: archiveTar.TypeReg,
	}
	if err := atw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := atw.Write([]byte("pwnd")); err != nil {
		t.Fatal(err)
	}
	atw.Close()
	f.Close()

	extractDir := filepath.Join(dir, "safe")
	os.MkdirAll(extractDir, 0755)
	err = ExtractFile(extractDir, tarPath, nil)
	if err == nil {
		t.Fatal("expected error for path traversal, got nil")
	}
}

func TestEmptyFile(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, "empty.txt"), []byte{}, 0644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := Create(&buf, []string{filepath.Join(dir, "empty.txt")}, nil); err != nil {
		t.Fatal(err)
	}

	extractDir := filepath.Join(dir, "out")
	os.MkdirAll(extractDir, 0755)
	if err := Extract(extractDir, &buf, nil); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(filepath.Join(extractDir, "empty.txt"))
	if len(data) != 0 {
		t.Fatalf("expected empty file, got %d bytes", len(data))
	}
}

func TestSymlink(t *testing.T) {
	dir := t.TempDir()

	srcFile := filepath.Join(dir, "target.txt")
	if err := os.WriteFile(srcFile, []byte("symlinked"), 0644); err != nil {
		t.Fatal(err)
	}
	linkPath := filepath.Join(dir, "mylink")
	if err := os.Symlink("target.txt", linkPath); err != nil {
		t.Skip("symlinks not supported on this platform")
	}

	var buf bytes.Buffer
	if err := Create(&buf, []string{linkPath}, nil); err != nil {
		t.Fatal(err)
	}

	extractDir := filepath.Join(dir, "out")
	os.MkdirAll(extractDir, 0755)
	if err := Extract(extractDir, &buf, nil); err != nil {
		t.Fatal(err)
	}

	target, err := os.Readlink(filepath.Join(extractDir, "mylink"))
	if err != nil {
		t.Fatal(err)
	}
	if target != "target.txt" {
		t.Fatalf("symlink target mismatch: got %q, want %q", target, "target.txt")
	}
}

func TestGzipStreamRoundtrip(t *testing.T) {
	dir := t.TempDir()

	srcFile := filepath.Join(dir, "gzip_stream.txt")
	if err := os.WriteFile(srcFile, []byte("gzip streaming data"), 0644); err != nil {
		t.Fatal(err)
	}

	opts := &Options{Compression: GzipCompression}
	var buf bytes.Buffer
	if err := Create(&buf, []string{srcFile}, opts); err != nil {
		t.Fatal(err)
	}
	if buf.Len() == 0 {
		t.Fatal("gzip stream produced empty output")
	}

	extractDir := filepath.Join(dir, "extracted")
	os.MkdirAll(extractDir, 0755)
	if err := Extract(extractDir, &buf, opts); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(filepath.Join(extractDir, "gzip_stream.txt"))
	if string(data) != "gzip streaming data" {
		t.Fatalf("got %q", string(data))
	}
}

func TestNonexistentSource(t *testing.T) {
	var buf bytes.Buffer
	err := Create(&buf, []string{"/nonexistent/path"}, nil)
	if err == nil {
		t.Fatal("expected error for nonexistent source")
	}
}

func TestExtractToNewDirectory(t *testing.T) {
	dir := t.TempDir()

	srcFile := filepath.Join(dir, "newdir_test.txt")
	if err := os.WriteFile(srcFile, []byte("new dir test"), 0644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := Create(&buf, []string{srcFile}, nil); err != nil {
		t.Fatal(err)
	}

	// Extract to a directory that does not exist yet.
	extractDir := filepath.Join(dir, "new", "nested", "dir")
	if err := Extract(extractDir, &buf, nil); err != nil {
		t.Fatalf("extract to new dir failed: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(extractDir, "newdir_test.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "new dir test" {
		t.Fatalf("got %q, want %q", string(data), "new dir test")
	}
}

func TestSymlinkPathTraversal(t *testing.T) {
	dir := t.TempDir()

	// Create a file outside the extraction root.
	leakFile := filepath.Join(dir, "leaked.txt")
	if err := os.WriteFile(leakFile, []byte("sensitive"), 0644); err != nil {
		t.Fatal(err)
	}

	tarPath := filepath.Join(dir, "symbad.tar")
	f, err := os.Create(tarPath)
	if err != nil {
		t.Fatal(err)
	}

	atw := archiveTar.NewWriter(f)
	hdr := &archiveTar.Header{
		Name:     "safe/evil-link",
		Size:     0,
		Mode:     0644,
		Typeflag: archiveTar.TypeSymlink,
		Linkname: "../../leaked.txt",
	}
	if err := atw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	atw.Close()
	f.Close()

	extractDir := filepath.Join(dir, "safe-extract")
	os.MkdirAll(extractDir, 0755)
	err = ExtractFile(extractDir, tarPath, nil)
	if err != nil {
		t.Fatalf("symlink traversal should not error (link points outside but that's allowed): %v", err)
	}

	// Verify the symlink was created pointing outside.
	target, err := os.Readlink(filepath.Join(extractDir, "safe", "evil-link"))
	if err != nil {
		t.Fatal(err)
	}
	if target != "../../leaked.txt" {
		t.Fatalf("expected symlink target, got %q", target)
	}
}

func TestGzipMismatch(t *testing.T) {
	dir := t.TempDir()

	srcFile := filepath.Join(dir, "gzip_mismatch.txt")
	if err := os.WriteFile(srcFile, []byte("gzip test"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create gzip tar.
	opts := &Options{Compression: GzipCompression}
	var buf bytes.Buffer
	if err := Create(&buf, []string{srcFile}, opts); err != nil {
		t.Fatal(err)
	}

	// Try to extract without gzip decompression (should produce garbage tar).
	extractDir := filepath.Join(dir, "mismatch")
	os.MkdirAll(extractDir, 0755)
	err := Extract(extractDir, &buf, nil)
	if err == nil {
		t.Fatal("expected error extracting gzip data without gzip option")
	}
}

func TestLargeDirectoryTree(t *testing.T) {
	dir := t.TempDir()

	root := filepath.Join(dir, "root")
	// Create 20 files in nested directories under root/.
	for i := 0; i < 20; i++ {
		subdir := filepath.Join(root, fmt.Sprintf("dir%d", i/5))
		if err := os.MkdirAll(subdir, 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(subdir, fmt.Sprintf("file%d.txt", i)), []byte(fmt.Sprintf("content%d", i)), 0644); err != nil {
			t.Fatal(err)
		}
	}

	tarPath := filepath.Join(dir, "large.tar")
	if err := CreateFile(tarPath, []string{root}, nil); err != nil {
		t.Fatal(err)
	}

	extractDir := filepath.Join(dir, "restored")
	os.MkdirAll(extractDir, 0755)
	if err := ExtractFile(extractDir, tarPath, nil); err != nil {
		t.Fatal(err)
	}

	// Spot-check a few files.
	for i := 0; i < 20; i++ {
		subdir := fmt.Sprintf("dir%d", i/5)
		path := filepath.Join(extractDir, "root", subdir, fmt.Sprintf("file%d.txt", i))
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("file%d.txt missing: %v", i, err)
		}
		if string(data) != fmt.Sprintf("content%d", i) {
			t.Fatalf("file%d.txt: got %q", i, string(data))
		}
	}
}

func TestPathWithDotPrefix(t *testing.T) {
	dir := t.TempDir()

	// Create source directory as a relative path to test ./ prefix.
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origDir)

	os.MkdirAll("mydir", 0755)
	if err := os.WriteFile("mydir/dot.txt", []byte("dot prefix"), 0644); err != nil {
		t.Fatal(err)
	}

	var buf bytes.Buffer
	if err := Create(&buf, []string{"./mydir"}, nil); err != nil {
		t.Fatal(err)
	}

	extractDir := filepath.Join(dir, "out")
	os.MkdirAll(extractDir, 0755)
	if err := Extract(extractDir, &buf, nil); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(filepath.Join(extractDir, "mydir", "dot.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "dot prefix" {
		t.Fatalf("got %q, want %q", string(data), "dot prefix")
	}
}

func TestMultipleSourcesMixed(t *testing.T) {
	dir := t.TempDir()

	os.MkdirAll(filepath.Join(dir, "adir"), 0755)
	if err := os.WriteFile(filepath.Join(dir, "adir", "afile.txt"), []byte("adir file"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "bfile.txt"), []byte("root file"), 0644); err != nil {
		t.Fatal(err)
	}

	tarPath := filepath.Join(dir, "mixed.tar")
	if err := CreateFile(tarPath, []string{
		filepath.Join(dir, "adir"),
		filepath.Join(dir, "bfile.txt"),
	}, nil); err != nil {
		t.Fatal(err)
	}

	extractDir := filepath.Join(dir, "extracted")
	os.MkdirAll(extractDir, 0755)
	if err := ExtractFile(extractDir, tarPath, nil); err != nil {
		t.Fatal(err)
	}

	data, _ := os.ReadFile(filepath.Join(extractDir, "adir", "afile.txt"))
	if string(data) != "adir file" {
		t.Fatalf("adir file: got %q", string(data))
	}
	data, _ = os.ReadFile(filepath.Join(extractDir, "bfile.txt"))
	if string(data) != "root file" {
		t.Fatalf("root file: got %q", string(data))
	}
}
