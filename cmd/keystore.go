package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mrinjamul/go-encryptor/crypt"
	"github.com/mrinjamul/go-encryptor/utils"
	"github.com/spf13/cobra"
)

const defaultKeyFile = ".default"

func keystoreDir() (string, error) {
	cfgDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(cfgDir, "go-encryptor", "keystore"), nil
}

func ensureKeystoreDir() (string, error) {
	dir, err := keystoreDir()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func keyPath(name string) (string, error) {
	dir, err := keystoreDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

func sanitizeKeyName(name string) string {
	return strings.NewReplacer(
		"/", "_",
		"\\", "_",
		"..", "_",
	).Replace(name)
}

func defaultKeyPath() (string, error) {
	dir, err := keystoreDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, defaultKeyFile), nil
}

func defaultKeyName() (string, error) {
	p, err := defaultKeyPath()
	if err != nil {
		return "", err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

func setDefaultKey(name string) error {
	p, err := defaultKeyPath()
	if err != nil {
		return err
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	return os.WriteFile(p, []byte(strings.TrimSpace(name)+"\n"), 0600)
}

func clearDefaultKey() error {
	p, err := defaultKeyPath()
	if err != nil {
		return err
	}
	if err := os.Remove(p); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func loadKey(name string) (crypt.PrivateKey, error) {
	name = sanitizeKeyName(name)
	p, err := keyPath(name)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, fmt.Errorf("key %q not found in keystore", name)
	}
	entry, err := crypt.UnmarshalKeyStoreEntry(data)
	if err != nil {
		return nil, err
	}
	return crypt.EntryToPrivateKey(entry)
}

func saveKey(name string, priv crypt.PrivateKey, label string) error {
	p, err := keyPath(name)
	if err != nil {
		return err
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	entry := &crypt.KeyStoreEntry{
		Type:    priv.KeyType(),
		Label:   label,
		Private: priv.PrivateBytes(),
		Public:  priv.PublicBytes(),
	}
	data := crypt.MarshalKeyStoreEntry(entry)
	return os.WriteFile(p, data, 0600)
}

func keyPublicString(priv crypt.PrivateKey) string {
	switch priv.KeyType() {
	case crypt.KeyTypeX25519:
		return crypt.PublicKeyToRecipient(priv.PublicBytes())
	case crypt.KeyTypeRSA:
		pub := priv.PublicBytes()
		if len(pub) > 16 {
			return fmt.Sprintf("rsa-pkix %02x%02x...%02x%02x", pub[0], pub[1], pub[len(pub)-2], pub[len(pub)-1])
		}
		return "rsa-pkix (unknown)"
	default:
		return "unknown"
	}
}

func keyTypeName(kt crypt.KeyType) string {
	switch kt {
	case crypt.KeyTypeX25519:
		return "X25519"
	case crypt.KeyTypeRSA:
		return "RSA"
	default:
		return "Unknown"
	}
}

func deleteKey(name string) error {
	p, err := keyPath(name)
	if err != nil {
		return err
	}
	if err := utils.SecureDelete(p); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("key %q not found in keystore", name)
		}
		return err
	}
	dflt, _ := defaultKeyName()
	if dflt == name {
		clearDefaultKey()
	}
	return nil
}

func listKeys() ([]string, error) {
	dir, err := keystoreDir()
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if e.Name() == defaultKeyFile || e.IsDir() {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	return names, nil
}

var keystoreCmd = &cobra.Command{
	Use:   "keystore",
	Short: "Manage stored encryption keys",
	Long: `Manage key pairs in the platform keystore.

Keys are stored in:
  Linux:   ~/.config/go-encryptor/keystore/
  macOS:   ~/Library/Application Support/go-encryptor/keystore/
  Windows: %AppData%/go-encryptor/keystore/

Supports X25519 (generated) and RSA (imported) keys.
The default key is tried first by decrypt when no -i flag is given.`,
	Run: func(cmd *cobra.Command, args []string) {
		cmd.Help()
	},
}

var keystoreAddCmd = &cobra.Command{
	Use:   "add <name> [identity-file]",
	Short: "Add a key to the keystore",
	Long: `Add a key to the keystore.

With no identity-file argument, a new X25519 key pair is generated.
With an identity-file argument, the key is imported (supports go-encryptor native format,
OpenSSH private keys: Ed25519 and RSA).

The first key added automatically becomes the default key.`,
	Args: cobra.RangeArgs(1, 2),
	Run: func(cmd *cobra.Command, args []string) {
		name := sanitizeKeyName(args[0])
		var priv crypt.PrivateKey
		var label string
		var err error

		if len(args) == 2 {
			data, readErr := os.ReadFile(args[1])
			if readErr != nil {
				utils.ErrorLogger(fmt.Errorf("reading identity file: %w", readErr))
				os.Exit(1)
			}
			entry, entryErr := crypt.UnmarshalKeyStoreEntry(data)
			if entryErr == nil {
				priv, err = crypt.EntryToPrivateKey(entry)
				label = entry.Label
			} else {
				id, idErr := crypt.UnmarshalIdentity(data)
				if idErr == nil {
					priv = id
					label = id.Label
				} else {
					priv, err = crypt.ParseSSHIdentity(data)
					if err != nil {
						utils.ErrorLogger(fmt.Errorf("failed to parse identity: %w", err))
						os.Exit(1)
					}
				}
			}
			if err != nil {
				utils.ErrorLogger(err)
				os.Exit(1)
			}
			fmt.Printf("Imported %s key %q from %s\n", keyTypeName(priv.KeyType()), name, args[1])
		} else {
			id, genErr := crypt.GenerateIdentity(fmt.Sprintf("keystore:%s", name))
			if genErr != nil {
				utils.ErrorLogger(genErr)
				os.Exit(1)
			}
			priv = id
			label = id.Label
			fmt.Printf("Generated new X25519 key %q\n", name)
		}

		if err := saveKey(name, priv, label); err != nil {
			utils.ErrorLogger(fmt.Errorf("saving key: %w", err))
			os.Exit(1)
		}

		existing, _ := defaultKeyName()
		if existing == "" {
			setDefaultKey(name)
			fmt.Printf("Set %q as the default key\n", name)
		}

		fmt.Printf("Public key: %s\n", keyPublicString(priv))
	},
}

var keystoreListCmd = &cobra.Command{
	Use:   "list",
	Short: "List all keys in the keystore",
	Args:  cobra.NoArgs,
	Run: func(cmd *cobra.Command, args []string) {
		names, err := listKeys()
		if err != nil {
			utils.ErrorLogger(err)
			os.Exit(1)
		}
		if len(names) == 0 {
			fmt.Println("Keystore is empty")
			return
		}
		dflt, _ := defaultKeyName()
		for _, name := range names {
			marker := ""
			if name == dflt {
				marker = " (default)"
			}
			priv, loadErr := loadKey(name)
			if loadErr != nil {
				fmt.Printf("  %-20s  (unable to load: %v)\n", name, loadErr)
				continue
			}
			fmt.Printf("  %-20s %-8s %s%s\n", name, keyTypeName(priv.KeyType()), keyPublicString(priv), marker)
		}
	},
}

var keystoreShowCmd = &cobra.Command{
	Use:   "show <name>",
	Short: "Show details of a key in the keystore",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		name := sanitizeKeyName(args[0])
		priv, err := loadKey(name)
		if err != nil {
			utils.ErrorLogger(err)
			os.Exit(1)
		}
		dflt, _ := defaultKeyName()
		isDefault := ""
		if name == dflt {
			isDefault = " (default)"
		}
		fmt.Printf("Name:       %s%s\n", name, isDefault)
		fmt.Printf("Type:       %s\n", keyTypeName(priv.KeyType()))
		fmt.Printf("Public key: %s\n", keyPublicString(priv))
	},
}

var keystoreRemoveCmd = &cobra.Command{
	Use:   "remove <name>",
	Short: "Remove a key from the keystore",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		name := sanitizeKeyName(args[0])
		if err := deleteKey(name); err != nil {
			utils.ErrorLogger(err)
			os.Exit(1)
		}
		fmt.Printf("Removed key %q\n", name)
	},
}

var keystoreExportCmd = &cobra.Command{
	Use:   "export <name> -o <file>",
	Short: "Export a key from the keystore to an identity file",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		name := sanitizeKeyName(args[0])
		priv, err := loadKey(name)
		if err != nil {
			utils.ErrorLogger(err)
			os.Exit(1)
		}
		entry := &crypt.KeyStoreEntry{
			Type:    priv.KeyType(),
			Public:  priv.PublicBytes(),
			Private: priv.PrivateBytes(),
		}
		data := crypt.MarshalKeyStoreEntry(entry)
		output := exportOutput
		if output == "" {
			output = name + "-identity"
		}
		if err := os.WriteFile(output, data, 0600); err != nil {
			utils.ErrorLogger(err)
			os.Exit(1)
		}
		fmt.Printf("Exported key %q to %s\n", name, output)
	},
}

var exportOutput string

var keystoreDefaultCmd = &cobra.Command{
	Use:   "default <name>",
	Short: "Set the default key for decryption",
	Long: `Set the default key tried first by decrypt
when no -i flag is given.`,
	Args: cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		name := sanitizeKeyName(args[0])
		if _, err := loadKey(name); err != nil {
			utils.ErrorLogger(err)
			os.Exit(1)
		}
		if err := setDefaultKey(name); err != nil {
			utils.ErrorLogger(err)
			os.Exit(1)
		}
		fmt.Printf("Set %q as the default key\n", name)
	},
}

func init() {
	rootCmd.AddCommand(keystoreCmd)

	keystoreCmd.AddCommand(keystoreAddCmd)
	keystoreCmd.AddCommand(keystoreListCmd)
	keystoreCmd.AddCommand(keystoreShowCmd)
	keystoreCmd.AddCommand(keystoreRemoveCmd)
	keystoreCmd.AddCommand(keystoreExportCmd)
	keystoreCmd.AddCommand(keystoreDefaultCmd)

	keystoreExportCmd.Flags().StringVarP(&exportOutput, "output", "o", "", "Output path (default: <name>-identity)")
}
