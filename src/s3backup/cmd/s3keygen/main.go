package main

import (
	"fmt"
	"log"
	"os"

	"s3backup/crypto"
	"s3backup/version"

	"github.com/spf13/cobra"
)

func main() {
	var cmdVersion = &cobra.Command{
		Use:   "version",
		Short: "Print version",
		Run: func(_ *cobra.Command, _ []string) {
			fmt.Println(version.Commit())
		},
	}

	var cmdGenAES = &cobra.Command{
		Use:   "aes",
		Short: "Print generated AES key",
		RunE: func(_ *cobra.Command, _ []string) error {
			key, err := crypto.GenerateAESKeyString()
			if err != nil {
				return err
			}
			fmt.Println(key)
			return nil
		},
	}

	var privKeyFile, pubKeyFile string

	var cmdGenRSA = &cobra.Command{
		Use:   "rsa",
		Short: "Generate RSA key pair",
		RunE: func(_ *cobra.Command, _ []string) error {
			return crypto.GenerateRSAKeyPair(privKeyFile, pubKeyFile)
		},
	}

	flags := cmdGenRSA.Flags()
	flags.StringVar(&privKeyFile, "priv", "private.pem", "Private key file for rsa key pair")
	flags.StringVar(&pubKeyFile, "pub", "public.pem", "Public key file for rsa key pair")

	var rootCmd = &cobra.Command{Use: "s3keygen"}
	rootCmd.AddCommand(cmdVersion, cmdGenAES, cmdGenRSA)

	if err := rootCmd.Execute(); err != nil {
		log.Fatalln(err)
		os.Exit(1)
	}
}
