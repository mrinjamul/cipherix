package tar

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Compression specifies the compression type for the tar archive.
type Compression int

const (
	NoCompression Compression = iota
	GzipCompression
)

// Options holds optional parameters for tar operations.
type Options struct {
	Compression Compression
}

// Create writes a tar archive of the given paths to w.
// paths may contain files and directories (directories are walked recursively).
func Create(w io.Writer, paths []string, opts *Options) error {
	if opts == nil {
		opts = &Options{}
	}

	var writer io.WriteCloser
	switch opts.Compression {
	case GzipCompression:
		writer = gzip.NewWriter(w)
	default:
		writer = writeNopCloser{w}
	}

	tw := tar.NewWriter(writer)
	for _, path := range paths {
		if err := addToArchive(tw, path); err != nil {
			tw.Close()
			if opts.Compression == GzipCompression {
				writer.Close()
			}
			return err
		}
	}

	if err := tw.Close(); err != nil {
		return err
	}
	if opts.Compression == GzipCompression {
		return writer.Close()
	}
	return nil
}

// CreateFile creates a tar archive at outputPath from the given paths.
func CreateFile(outputPath string, paths []string, opts *Options) error {
	f, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer f.Close()
	return Create(f, paths, opts)
}

// Extract reads a tar archive from r and extracts it into dest.
// It is safe against path traversal attacks.
func Extract(dest string, r io.Reader, opts *Options) error {
	if opts == nil {
		opts = &Options{}
	}

	var reader io.ReadCloser
	switch opts.Compression {
	case GzipCompression:
		var err error
		reader, err = gzip.NewReader(r)
		if err != nil {
			return err
		}
	default:
		reader = io.NopCloser(r)
	}
	defer reader.Close()

	tr := tar.NewReader(reader)
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		if err := extractEntry(dest, header, tr); err != nil {
			return err
		}
	}
	return nil
}

// ExtractFile reads a tar archive from archivePath and extracts it into dest.
func ExtractFile(dest string, archivePath string, opts *Options) error {
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	return Extract(dest, f, opts)
}

func addToArchive(tw *tar.Writer, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	var baseDir string
	if info.IsDir() {
		baseDir = filepath.Base(path)
	}

	return filepath.Walk(path, func(filePath string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Resolve symlink target.
		linkTarget := ""
		if fi.Mode()&os.ModeSymlink != 0 {
			linkTarget, err = os.Readlink(filePath)
			if err != nil {
				return err
			}
		}

		header, err := tar.FileInfoHeader(fi, linkTarget)
		if err != nil {
			return err
		}

		if baseDir != "" {
			rel, err := filepath.Rel(path, filePath)
			if err != nil {
				return err
			}
			header.Name = filepath.ToSlash(filepath.Join(baseDir, rel))
		} else {
			header.Name = filepath.ToSlash(filepath.Base(filePath))
		}

		if err := tw.WriteHeader(header); err != nil {
			return err
		}

		if fi.IsDir() || !fi.Mode().IsRegular() {
			return nil
		}

		f, err := os.Open(filePath)
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = io.Copy(tw, f)
		return err
	})
}

func extractEntry(dest string, header *tar.Header, tr *tar.Reader) error {
	cleanName := filepath.Clean(header.Name)
	if strings.Contains(cleanName, "..") {
		return fmt.Errorf("tar: invalid path %q", header.Name)
	}

	target := filepath.Join(dest, filepath.FromSlash(cleanName))
	if !strings.HasPrefix(target, filepath.Clean(dest)+string(os.PathSeparator)) &&
		target != filepath.Clean(dest) {
		return fmt.Errorf("tar: path %q escapes destination", header.Name)
	}

	switch header.Typeflag {
	case tar.TypeDir:
		return os.MkdirAll(target, os.FileMode(header.Mode))

	case tar.TypeReg:
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		f, err := os.OpenFile(target, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(header.Mode))
		if err != nil {
			return err
		}
		defer f.Close()

		_, err = io.Copy(f, tr)
		return err

	case tar.TypeSymlink:
		if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
			return err
		}
		return os.Symlink(header.Linkname, target)

	default:
		return fmt.Errorf("tar: unsupported type %c in %s", header.Typeflag, header.Name)
	}
}

type writeNopCloser struct {
	io.Writer
}

func (writeNopCloser) Close() error { return nil }
