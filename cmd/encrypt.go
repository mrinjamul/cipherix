/*
Copyright © 2021 Injamul Mohammad Mollah <mrinjamul@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/
package cmd

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"

	"github.com/mrinjamul/cipherix/crypt"
	"github.com/mrinjamul/cipherix/lib/tar"
	"github.com/mrinjamul/cipherix/utils"
	"github.com/spf13/cobra"
)

var (
	parallelMode bool
	noProgress   bool
	cleanupFiles []string
	cleanupMu    sync.Mutex
)

func init() {
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		cleanupMu.Lock()
		for _, f := range cleanupFiles {
			os.Remove(f)
		}
		cleanupMu.Unlock()
		os.Exit(1)
	}()
}

func addCleanupFile(path string) {
	cleanupMu.Lock()
	cleanupFiles = append(cleanupFiles, path)
	cleanupMu.Unlock()
}

func removeCleanupFile(path string) {
	cleanupMu.Lock()
	for i, f := range cleanupFiles {
		if f == path {
			cleanupFiles = append(cleanupFiles[:i], cleanupFiles[i+1:]...)
			break
		}
	}
	cleanupMu.Unlock()
}

// lookupRecipient tries to find a key in the keystore by name, converting it
// to a Recipient. Returns os.IsNotExist errors for not-found.
// Skips lookup for inline key formats or overly long strings.
func lookupRecipient(name string) (crypt.Recipient, error) {
	if strings.HasPrefix(name, "cphx") || strings.HasPrefix(name, "ssh-") || len(name) > 64 {
		return nil, os.ErrNotExist
	}
	name = sanitizeKeyName(name)
	p, err := keyPath(name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	entry, err := crypt.UnmarshalKeyStoreEntry(data)
	if err != nil {
		return nil, err
	}
	return crypt.EntryToRecipient(entry)
}

// lookupDefaultKeystoreRecipient returns a Recipient from the default keystore key.
// Returns (nil, nil) when no default key exists (not an error).
func lookupDefaultKeystoreRecipient() (crypt.Recipient, error) {
	dflt, err := defaultKeyName()
	if err != nil || dflt == "" {
		return nil, nil
	}
	p, err := keyPath(dflt)
	if err != nil {
		return nil, nil
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, nil
	}
	entry, err := crypt.UnmarshalKeyStoreEntry(data)
	if err != nil {
		return nil, nil
	}
	return crypt.EntryToRecipient(entry)
}

// encryptToRecipients resolves all -r flags (keystore lookup → file → inline)
// and encrypts data.
func encryptToRecipients(data []byte, extension string) ([]byte, error) {
	var pubs []crypt.Recipient
	for _, r := range recipientOpt {
		pubKey, err := lookupRecipient(r)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
			// Not in keystore, try as file path (identity, SSH key, or inline key)
			var fileData []byte
			if fd, readErr := os.ReadFile(r); readErr == nil {
				fileData = fd
				r = strings.TrimSpace(string(fd))
			}
			pubKey, err = crypt.RecipientToPublicKey(r)
			if err != nil {
				pubKey, err = crypt.ParseSSHRecipient(r)
			}
			if err != nil && len(fileData) > 0 {
				var id *crypt.Identity
				id, err = crypt.UnmarshalIdentity(fileData)
				if err == nil {
					pubKey, err = crypt.NewX25519Recipient(id.Public)
				}
			}
			if err != nil && len(fileData) > 0 {
				var priv crypt.PrivateKey
				priv, err = crypt.ParseSSHIdentity(fileData)
				if err == nil {
					pubKey, err = crypt.PrivateKeyToRecipient(priv)
				}
			}
		}
		if err != nil {
			return nil, fmt.Errorf("invalid recipient: %w", err)
		}
		pubs = append(pubs, pubKey)
	}
	if len(pubs) == 1 {
		return crypt.EncryptToPublicKey(pubs[0], data, extension)
	}
	return crypt.EncryptToPublicKeys(pubs, data, extension)
}

// outputMu protects per-file output lines from interleaving in parallel mode.
var outputMu sync.Mutex

// encryptCmd represents the encrypt command
var encryptCmd = &cobra.Command{
	Use:     "encrypt",
	Aliases: []string{"en"},
	Short:   "Encrypt file or folder",
	Long:    `Encrypt file using specified method. (Default: AES)`,
	Run:     encryptRun,
}

func encryptRun(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fi, err := os.Stdin.Stat()
		if err == nil && (fi.Mode()&os.ModeCharDevice) == 0 {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				utils.ErrorLogger(err)
				os.Exit(1)
			}
			encryptStdin(data)
			return
		}
		fmt.Fprintln(os.Stderr, "Error: missing file argument")
		fmt.Println("Usage: " + utils.AppName + " encrypt [filename]")
		os.Exit(1)
	}

	// Expand glob patterns.
	var files []string
	for _, arg := range args {
		matches, err := filepath.Glob(arg)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: invalid file pattern %q\n", arg)
			os.Exit(1)
		}
		if len(matches) == 0 {
			fmt.Fprintf(os.Stderr, "Error: %q: no matching files\n", arg)
			os.Exit(1)
		}
		files = append(files, matches...)
	}

	// Parallel per-file processing (skip for interactive or single-file).
	hasDefaultKey, _ := defaultKeyName()
	needsPrompt := passwordOpt == "" && passwordEnv == "" && len(recipientOpt) == 0 && hasDefaultKey == ""
	parallelMode = outputOpt == "" && !needsPrompt && len(files) > 1
	if outputOpt != "" || needsPrompt || len(files) <= 1 {
		for _, fileName := range files {
			encryptFile(fileName)
		}
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.NumCPU())
	for _, fileName := range files {
		sem <- struct{}{}
		wg.Add(1)
		go func(f string) {
			defer wg.Done()
			defer func() { <-sem }()
			encryptFile(f)
		}(fileName)
	}
	wg.Wait()
}

func encryptFile(fileName string) {
	// check if file exists
	if _, err := os.Stat(fileName); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: %s: file not found\n", fileName)
		os.Exit(1)
	}

	origName := strings.TrimSuffix(fileName, "/")

	// Check if argument is directory
	isDirectory, err := utils.IsDir(origName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %s: file not found\n", origName)
		os.Exit(1)
	}

	var tarName string

	filename, extension := utils.GetFileNameExt(origName)
	encryptFileName := filename + AppExtension
	if outputOpt != "" {
		encryptFileName = outputOpt
	}

	// Resolve password.
	var password []byte
	defer func() { utils.ZeroBytes(password) }()
	if passwordEnv != "" {
		p := os.Getenv(passwordEnv)
		if p == "" {
			fmt.Fprintf(os.Stderr, "Error: environment variable %s is not set or is empty\n", passwordEnv)
			os.Exit(1)
		}
		password = []byte(p)
	} else if passwordOpt != "" {
		password = []byte(passwordOpt)
	}
	var keystoreRecipient crypt.Recipient
	usePassword := len(password) > 0 || len(recipientOpt) == 0

	if usePassword && len(password) == 0 && len(recipientOpt) == 0 {
		keystoreRecipient, _ = lookupDefaultKeystoreRecipient()
	}

	if usePassword && len(password) == 0 && keystoreRecipient == nil {
		password, err = utils.PromptTermPass("Password: ")
		if err != nil {
			utils.ErrorLogger(err)
			os.Exit(1)
		}
		if len(password) < 8 {
			fmt.Println("Warning: Password should be at least 8 characters")
		}
		verifyPassword, err := utils.PromptTermPass("Verify Password: ")
		if err != nil {
			utils.ErrorLogger(err)
			os.Exit(1)
		}
		if string(verifyPassword) != string(password) {
			fmt.Fprintln(os.Stderr, "Error: passwords do not match")
			os.Exit(1)
		}
		entropy := utils.PasswordEntropy(password)
		if entropy < 40 {
			fmt.Printf("Warning: Password entropy is low (%.0f bits). Consider a stronger password.\n", entropy)
		}
	}

	if isDirectory {
		extension = "tez"
		tarDir := filepath.Dir(origName)
		tarBase := filepath.Base(origName)
		tarFile, err := os.CreateTemp(tarDir, tarBase+".tez-")
		if err != nil {
			utils.ErrorLogger(err)
			os.Exit(1)
		}
		tarName = tarFile.Name()
		tarFile.Close()
		addCleanupFile(tarName)
		err = tar.CreateFile(tarName, []string{origName}, nil)
		if err != nil {
			removeCleanupFile(tarName)
			utils.SecureDelete(tarName)
			utils.ErrorLogger(err)
			os.Exit(1)
		}
		fileName = tarName
	} else {
		fileName = origName
	}

	f, err := os.Open(fileName)
	if err != nil {
		utils.ErrorLogger(err)
		os.Exit(1)
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		utils.ErrorLogger(err)
		os.Exit(1)
	}
	pr := utils.NewProgressReader(f, fi.Size(), "Reading", parallelMode || noProgress)
	data, err := io.ReadAll(pr)
	f.Close()
	if err != nil {
		utils.ErrorLogger(err)
		os.Exit(1)
	}
	pr.Done()

	var encryptdata []byte
	if len(recipientOpt) > 0 {
		encryptdata, err = encryptToRecipients(data, extension)
		if err != nil {
			utils.ErrorLogger(err)
			os.Exit(1)
		}
	} else if keystoreRecipient != nil {
		encryptdata, err = crypt.EncryptToPublicKey(keystoreRecipient, data, extension)
		if err != nil {
			utils.ErrorLogger(err)
			os.Exit(1)
		}
	} else {
		encryptdata, err = crypt.Encrypt(password, data, methodOpt, extension)
		if err != nil {
			utils.ErrorLogger(err)
			os.Exit(1)
		}
	}

	if armorOpt {
		encryptdata = utils.ArmorEncode(encryptdata)
	}
	utils.SaveFile(encryptFileName, encryptdata)
	if isDirectory {
		err = utils.SecureDelete(tarName)
		if err != nil {
			utils.ErrorLogger(err)
		}
		removeCleanupFile(tarName)
	}
	outputMu.Lock()
	fmt.Println(fileName + " encrypted successfully.")
	outputMu.Unlock()

	if !keepenOpt {
		if !isDirectory {
			err := utils.SecureDelete(origName)
			if err != nil {
				utils.ErrorLogger(err)
			}
		} else {
			err := os.RemoveAll(origName)
			if err != nil {
				utils.ErrorLogger(err)
			}
		}
	}
}

func encryptStdin(data []byte) {
	var password []byte
	if passwordEnv != "" {
		p := os.Getenv(passwordEnv)
		if p == "" {
			fmt.Fprintf(os.Stderr, "Error: environment variable %s is not set or is empty\n", passwordEnv)
			os.Exit(1)
		}
		password = []byte(p)
	} else if passwordOpt != "" {
		password = []byte(passwordOpt)
	}
	usePassword := len(password) > 0 || len(recipientOpt) == 0

	var keystoreRecipient crypt.Recipient
	if usePassword && len(password) == 0 && len(recipientOpt) == 0 {
		keystoreRecipient, _ = lookupDefaultKeystoreRecipient()
	}

	if usePassword && len(password) == 0 && keystoreRecipient == nil {
		fmt.Fprintln(os.Stderr, "Error: password required when reading from stdin (use -p, --password-env, or a keystore default key)")
		os.Exit(1)
	}

	extension := "bin"

	var encryptdata []byte
	var err error
	if len(recipientOpt) > 0 {
		encryptdata, err = encryptToRecipients(data, extension)
	} else if keystoreRecipient != nil {
		encryptdata, err = crypt.EncryptToPublicKey(keystoreRecipient, data, extension)
	} else {
		encryptdata, err = crypt.Encrypt(password, data, methodOpt, extension)
	}
	if err != nil {
		utils.ErrorLogger(err)
		os.Exit(1)
	}

	if armorOpt {
		encryptdata = utils.ArmorEncode(encryptdata)
	}
	if outputOpt != "" {
		utils.SaveFile(outputOpt, encryptdata)
	} else {
		os.Stdout.Write(encryptdata)
	}
}

var (
	keepenOpt       bool
	armorOpt        bool
	methodOpt       string
	passwordOpt     string
	passwordEnv     string
	recipientOpt    []string
	outputOpt       string
)

func init() {
	rootCmd.AddCommand(encryptCmd)

	encryptCmd.Flags().BoolVarP(&keepenOpt, "keep", "k", false, "Keep uncrypted file")
	encryptCmd.Flags().BoolVarP(&armorOpt, "armor", "a", false, "Encode encrypted data as ASCII armor")
	encryptCmd.Flags().StringVarP(&methodOpt, "method", "m", "aes", "Encryption method (aes, chacha20)")
	encryptCmd.Flags().StringVarP(&passwordOpt, "password", "p", "", "Password")
	encryptCmd.Flags().StringVarP(&passwordEnv, "password-env", "", "", "Read password from environment variable")
	encryptCmd.Flags().StringArrayVarP(&recipientOpt, "recipient", "r", nil, "Encrypt to public key: keystore name, cphx... string, SSH key file, or inline SSH key (repeatable)")
	encryptCmd.Flags().StringVarP(&outputOpt, "output", "o", "", "Output file path")
	encryptCmd.Flags().BoolVar(&noProgress, "no-progress", false, "Disable progress bar")

	methodOpt = strings.ToLower(methodOpt)
	if methodOpt != "aes" && methodOpt != "chacha20" && methodOpt != "xchacha20" {
		fmt.Fprintln(os.Stderr, "Error: unsupported encryption method (use: aes, chacha20, xchacha20)")
		os.Exit(1)
	}
}
