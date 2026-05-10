package cmd

import (
	"fmt"
	"os"

	"github.com/mrinjamul/cipherix/crypt"
	"github.com/mrinjamul/cipherix/utils"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(inspectCmd)
}

var inspectCmd = &cobra.Command{
	Use:   "inspect <encrypted-file>",
	Aliases: []string{"ins"},
	Short: "Display metadata about an encrypted file",
	Long:  "Display metadata about an encrypted file without decrypting it.",
	Args:  cobra.ExactArgs(1),
	Run:   inspectRun,
}

func inspectRun(cmd *cobra.Command, args []string) {
	fileName := args[0]

	data, err := utils.ReadFile(fileName)
	if err != nil {
		utils.ErrorLogger(err)
		os.Exit(1)
	}

	wasArmored := false
	if utils.IsArmored(data) {
		wasArmored = true
		data, err = utils.ArmorDecode(data)
		if err != nil {
			utils.ErrorLogger(err)
			os.Exit(1)
		}
	}

	fi, err := crypt.InspectFileInfo(data)
	if err != nil {
		utils.ErrorLogger(err)
		os.Exit(1)
	}

	typeStr := "file"
	if fi.Extension == "tez" {
		typeStr = "folder"
	} else if fi.Extension != "" {
		typeStr = fmt.Sprintf("file (.%s)", fi.Extension)
	}

	keyType := "password"
	if fi.NumRecipients > 0 {
		keyType = "pubkey"
	}

	methodName := methodDisplay(fi.Algorithm)
	fileInfo, _ := os.Stat(fileName)
	fileSize := fileInfo.Size()

	armoredStr := "no"
	if wasArmored {
		armoredStr = "yes"
	}

	fmt.Printf("File:    %s\n", fileName)
	fmt.Printf("Format:  %d\n", fi.FormatVersion)
	fmt.Printf("Method:  %s (%s)\n", methodName, keyType)
	fmt.Printf("KDF:     %s\n", fi.KDF)
	fmt.Printf("Type:    %s\n", typeStr)
	fmt.Printf("Size:    %s\n", utils.FormatBytes(fileSize))
	fmt.Printf("Armored: %s\n", armoredStr)
	if fi.NumRecipients > 0 {
		fmt.Printf("Recipients: %d\n", fi.NumRecipients)
		for i, id := range fi.RecipientIDs {
			fmt.Printf("  recipient %d: %s\n", i+1, id)
		}
	}
}

func methodDisplay(algo string) string {
	switch algo {
	case "aes":
		return "AES-256-GCM"
	case "chacha20":
		return "XChaCha20-Poly1305"
	case "pubkey":
		return "X25519 ECDH"
	case "pubkey-multi":
		return "X25519 ECDH (multi-recipient)"
	case "pubkey-rsa":
		return "RSA-OAEP"
	case "pubkey-rsa-multi":
		return "RSA-OAEP (multi-recipient)"
	case "pubkey-hybrid":
		return "Hybrid (RSA + X25519)"
	default:
		return algo
	}
}
