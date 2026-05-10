package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/mrinjamul/go-encryptor/crypt"
	"github.com/mrinjamul/go-encryptor/utils"
	"github.com/spf13/cobra"
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate a new encryption key pair",
	Long: `Generate a new X25519 key pair for public-key encryption.
The identity file can be used with -i/--identity for decryption,
and the public key can be shared as a recipient with -r/--recipient.`,
	Run: keygenRun,
}

var (
	keygenOutput     string
	keygenProtect    bool
	keygenComment    string
	showPubkey       bool
)

func keygenRun(cmd *cobra.Command, args []string) {
	id, err := crypt.GenerateIdentity(keygenComment)
	if err != nil {
		utils.ErrorLogger(err)
		os.Exit(1)
	}

	if showPubkey {
		fmt.Println(crypt.PublicKeyToRecipient(id.Public))
		return
	}

	data := crypt.MarshalIdentity(id)

	output := keygenOutput
	if output == "" {
		output = "go-encryptor-identity"
	}

	if err := os.WriteFile(output, data, 0600); err != nil {
		utils.ErrorLogger(err)
		os.Exit(1)
	}

	fmt.Printf("Identity written to %s\n", output)
	fmt.Printf("Public key: %s\n", crypt.PublicKeyToRecipient(id.Public))
	fmt.Println("Keep this file secret! Anyone with it can decrypt your files.")

	// Auto-add to keystore.
	keyName := filepath.Base(output)
	if err := saveKey(keyName, id, keygenComment); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: failed to add key to keystore: %v\n", err)
	} else {
		fmt.Printf("Added key to keystore as %q\n", keyName)
		existing, _ := defaultKeyName()
		if existing == "" {
			setDefaultKey(keyName)
			fmt.Printf("Set %q as the default key\n", keyName)
		}
	}
}

func init() {
	rootCmd.AddCommand(keygenCmd)
	keygenCmd.Flags().StringVarP(&keygenOutput, "output", "o", "", "Output path (default: go-encryptor-identity)")
	keygenCmd.Flags().StringVarP(&keygenComment, "comment", "c", "", "Identity comment/label")
	keygenCmd.Flags().BoolVarP(&showPubkey, "show-pubkey", "y", false, "Only show public key, do not write identity")
}
