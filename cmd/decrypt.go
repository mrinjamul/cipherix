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
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"github.com/mrinjamul/cipherix/crypt"
	"github.com/mrinjamul/cipherix/lib/tar"
	"github.com/mrinjamul/cipherix/utils"
	"github.com/spf13/cobra"
)

// decryptCmd represents the decrypt command
var decryptCmd = &cobra.Command{
	Use:     "decrypt",
	Aliases: []string{"de"},
	Short:   "Decrypt encrypted file",
	Long:    `Decrypt encrypted file using specified method. (Default: AES)`,
	Run:     decryptRun,
}

func decryptRun(cmd *cobra.Command, args []string) {
	if len(args) == 0 {
		fi, err := os.Stdin.Stat()
		if err == nil && (fi.Mode()&os.ModeCharDevice) == 0 {
			data, err := io.ReadAll(os.Stdin)
			if err != nil {
				utils.ErrorLogger(err)
				os.Exit(1)
			}
			decryptStdin(data)
			return
		}
		fmt.Fprintln(os.Stderr, "Error: missing file argument")
		fmt.Println("Usage: " + utils.AppName + " decrypt [filename]")
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
	needsPrompt := passwordOpt == "" && passwordEnv == "" && identityOpt == "" && hasDefaultKey == ""
	parallelMode = outputOpt == "" && !stdoutOpt && !needsPrompt && len(files) > 1
	if outputOpt != "" || stdoutOpt || needsPrompt || len(files) <= 1 {
		for _, file := range files {
			decryptFile(file)
		}
		return
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, runtime.NumCPU())
	for _, file := range files {
		sem <- struct{}{}
		wg.Add(1)
		go func(f string) {
			defer wg.Done()
			defer func() { <-sem }()
			decryptFile(f)
		}(file)
	}
	wg.Wait()
}

func decryptFile(encryptedfileName string) {
	// check if file exists
	if _, err := os.Stat(encryptedfileName); os.IsNotExist(err) {
		fmt.Fprintf(os.Stderr, "Error: %s: file not found\n", encryptedfileName)
		os.Exit(1)
	}

	filename, _ := utils.GetFileNameExt(encryptedfileName)

	// read encrypted data
	f, err := os.Open(encryptedfileName)
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
	encryptedData, err := io.ReadAll(pr)
	f.Close()
	if err != nil {
		utils.ErrorLogger(err)
		os.Exit(1)
	}
	pr.Done()

	if utils.IsArmored(encryptedData) {
		encryptedData, err = utils.ArmorDecode(encryptedData)
		if err != nil {
			utils.ErrorLogger(err)
			os.Exit(1)
		}
	}

	data, ext, err := decryptWithCascade(encryptedData, true)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: decryption failed — wrong password")
		os.Exit(1)
	}

	// print to stdout and return
	if stdoutOpt {
		binary.Write(os.Stdout, binary.LittleEndian, data)
		return
	}

	outPath := outputOpt
	if outPath == "" {
		if ext == "ger" {
			ext = ""
		}
		if ext != "" {
			outPath = filename + "." + ext
		} else {
			outPath = filename
		}
	}
	if ext == "tez" {
		extractDir := outputOpt
		if extractDir == "" {
			extractDir, err = os.Getwd()
			if err != nil {
				utils.ErrorLogger(err)
				os.Exit(1)
			}
		}
		if err := tar.Extract(extractDir, bytes.NewReader(data), nil); err != nil {
			utils.ErrorLogger(err)
			os.Exit(1)
		}
	} else {
		utils.SaveFile(outPath, data)
	}
	outputMu.Lock()
	fmt.Println(filename + " decrypted successfully.")
	outputMu.Unlock()

	if !keepdeOpt {
		err := utils.SecureDelete(encryptedfileName)
		if err != nil {
			utils.ErrorLogger(err)
		}
	}
}

func decryptStdin(encryptedData []byte) {
	if utils.IsArmored(encryptedData) {
		var err error
		encryptedData, err = utils.ArmorDecode(encryptedData)
		if err != nil {
			utils.ErrorLogger(err)
			os.Exit(1)
		}
	}

	data, _, err := decryptWithCascade(encryptedData, false)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error: password required when reading from stdin (use -p, --password-env, -i, or a keystore key)")
		os.Exit(1)
	}

	if outputOpt != "" {
		utils.SaveFile(outputOpt, data)
	} else {
		os.Stdout.Write(data)
	}
}

// decryptWithCascade tries decryption via identity, password from flag/env,
// keystore keys, and finally password prompt — falling through each on failure.
func decryptWithCascade(encryptedData []byte, allowPrompt bool) (data []byte, ext string, err error) {
	// Try identity from -i flag
	if identityOpt != "" {
		idRaw, readErr := utils.ReadFile(identityOpt)
		if readErr == nil {
			var id crypt.PrivateKey
			id, err = crypt.UnmarshalIdentity(idRaw)
			if err != nil {
				id, err = crypt.ParseSSHIdentity(idRaw)
			}
			if err == nil {
				data, ext, err = crypt.DecryptWithIdentity(id, encryptedData)
				if err == nil {
					return data, ext, nil
				}
			}
		} else {
			fmt.Fprintf(os.Stderr, "Warning: could not read identity file: %v\n", readErr)
		}
	}

	// Try password from --password-env or -p
	passwordTried := false
	if passwordOpt != "" || passwordEnv != "" {
		password, pwErr := resolvePassword()
		if pwErr == nil {
			passwordTried = true
			data, ext, err = crypt.Decrypt(password, encryptedData)
			utils.ZeroBytes(password)
			if err == nil {
				return data, ext, nil
			}
		}
	}

	// Try keystore keys
	data, ext, err = tryKeystoreKeys(encryptedData)
	if err == nil {
		return data, ext, nil
	}

	// Try password prompt (only if allowed and no usable password was obtained from flags)
	if allowPrompt && !passwordTried {
		password, pwErr := utils.PromptTermPass("Password: ")
		if pwErr == nil {
			data, ext, err = crypt.Decrypt(password, encryptedData)
			utils.ZeroBytes(password)
			if err == nil {
				return data, ext, nil
			}
		}
	}

	return nil, "", fmt.Errorf("all decryption methods failed")
}

// tryKeystoreKeys iterates all keys in the keystore and tries to decrypt.
// The default key is tried first; remaining keys are tried in list order.
func tryKeystoreKeys(encryptedData []byte) ([]byte, string, error) {
	keys, err := listKeys()
	if err != nil || len(keys) == 0 {
		return nil, "", fmt.Errorf("no keystore keys available")
	}

	dflt, _ := defaultKeyName()

	if dflt != "" {
		id, loadErr := loadKey(dflt)
		if loadErr == nil {
			data, ext, decryptErr := crypt.DecryptWithIdentity(id, encryptedData)
			if decryptErr == nil {
				outputMu.Lock()
				fmt.Printf("Using default key %q from keystore\n", dflt)
				outputMu.Unlock()
				return data, ext, nil
			}
		}
	}

	for _, name := range keys {
		if name == dflt {
			continue
		}
		id, loadErr := loadKey(name)
		if loadErr != nil {
			continue
		}
		data, ext, decryptErr := crypt.DecryptWithIdentity(id, encryptedData)
		if decryptErr == nil {
			outputMu.Lock()
			fmt.Printf("Using key %q from keystore\n", name)
			outputMu.Unlock()
			return data, ext, nil
		}
	}

	return nil, "", fmt.Errorf("no keystore key could decrypt the file")
}

// resolvePassword returns the password from --password-env or -p.
func resolvePassword() ([]byte, error) {
	if passwordEnv != "" {
		p := os.Getenv(passwordEnv)
		if p == "" {
			return nil, fmt.Errorf("environment variable %s is not set or is empty", passwordEnv)
		}
		return []byte(p), nil
	}
	if passwordOpt != "" {
		return []byte(passwordOpt), nil
	}
	return nil, fmt.Errorf("resolvePassword called without --password-env or -p")
}

var (
	keepdeOpt   bool
	stdoutOpt   bool
	identityOpt string
)

func init() {
	rootCmd.AddCommand(decryptCmd)

	decryptCmd.Flags().BoolVarP(&keepdeOpt, "keep", "k", false, "Keep encrypted file")
	decryptCmd.Flags().BoolVar(&stdoutOpt, "print", false, "Print decrypted data to stdout")
	decryptCmd.Flags().StringVarP(&methodOpt, "method", "m", "aes", "Encryption method (auto-detected if omitted)")
	decryptCmd.Flags().StringVarP(&passwordOpt, "password", "p", "", "Password")
	decryptCmd.Flags().StringVarP(&passwordEnv, "password-env", "", "", "Read password from environment variable")
	decryptCmd.Flags().StringVarP(&identityOpt, "identity", "i", "", "Identity file for decryption")
	decryptCmd.Flags().StringVarP(&outputOpt, "output", "o", "", "Output file path")
	decryptCmd.Flags().BoolVar(&noProgress, "no-progress", false, "Disable progress bar")
}
