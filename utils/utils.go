/*Package utils ...
 *
 */
package utils

import (
	"crypto/rand"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

// AppName is the application name
var AppName = "go-encryptor"

// ErrorLogger logs error
func ErrorLogger(err error) {
	fmt.Fprintln(os.Stderr, "Error:", err)
}

// PromptTermPass takes password as user input
func PromptTermPass(promptText string) ([]byte, error) {
	fmt.Print(promptText)
	bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		ErrorLogger(err)
		return []byte{}, err
	}
	return bytePassword, nil
}

// GetFileNameExt simplify filename for use (Note: only 3 char ext)
func GetFileNameExt(file string) (filename, extension string) {
	if len(file) > 4 && file[len(file)-4:len(file)-3] == "." {
		filename = file[0 : len(file)-4]
		extension = file[len(file)-3:]
	} else if len(file) > 3 && file[len(file)-3:len(file)-2] == "." {
		filename = file[0 : len(file)-3]
		extension = file[len(file)-2:]
	} else {
		filename = file
		extension = ""
	}
	return filename, extension
}

// ReadFile returns file data in bytes
func ReadFile(filename string) ([]byte, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return []byte{}, err
	}
	return data, nil
}

// SaveFile saves data to a file atomically.
// Writes to a temp file in the same directory first, then renames atomically
// to prevent partial writes and symlink attacks.
func SaveFile(filename string, data []byte) error {
	dir := filepath.Dir(filename)
	f, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	tmpName := f.Name()
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmpName)
		return err
	}
	if err := f.Chmod(0600); err != nil {
		f.Close()
		os.Remove(tmpName)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpName)
		return err
	}
	if err := os.Rename(tmpName, filename); err != nil {
		os.Remove(tmpName)
		return err
	}
	return nil
}

// IsDir is to check if its a dir
func IsDir(path string) (bool, error) {
	out, err := os.Stat(path)
	if err != nil {
		return false, err
	}
	return out.IsDir(), nil
}

// ConfirmPrompt will prompt to user for yes or no
func ConfirmPrompt(message string) bool {
	var response string
	fmt.Print(message + " (yes/no) :")
	fmt.Scanln(&response)

	switch strings.ToLower(response) {
	case "y", "yes":
		return true
	case "n", "no":
		return false
	default:
		return false
	}
}

// PasswordEntropy estimates password entropy in bits.
func PasswordEntropy(password []byte) float64 {
	hasLower := false
	hasUpper := false
	hasDigit := false
	hasSpecial := false
	for _, c := range password {
		switch {
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}
	poolSize := 0
	if hasLower {
		poolSize += 26
	}
	if hasUpper {
		poolSize += 26
	}
	if hasDigit {
		poolSize += 10
	}
	if hasSpecial {
		poolSize += 33
	}
	if poolSize == 0 {
		return 0
	}
	return math.Log2(float64(poolSize)) * float64(len(password))
}

// SecureDelete overwrites file contents with random data before removing.
// This helps prevent recovery of sensitive data from disk.
func SecureDelete(path string) error {
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		// If file doesn't exist, nothing to delete.
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return err
	}
	size := info.Size()

	// Overwrite with random data in 64 KiB chunks.
	buf := make([]byte, 64*1024)
	for written := int64(0); written < size; {
		remaining := size - written
		if remaining < int64(len(buf)) {
			buf = buf[:remaining]
		}
		if _, err := rand.Read(buf); err != nil {
			return err
		}
		if _, err := f.Write(buf); err != nil {
			return err
		}
		written += int64(len(buf))
		// Reset buffer to full capacity for next iteration.
		buf = buf[:cap(buf)]
	}

	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Remove(path)
}

// ZeroBytes clears a byte slice, zeroing sensitive data in memory.
// Safe to call with nil or empty slice.
func ZeroBytes(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}
