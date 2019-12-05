package main

import (
	"errors"
	"fmt"
	"log"

	"github.com/spf13/cobra"

	"github.com/tomcz/s3backup/client"
	"github.com/tomcz/s3backup/client/crypto"
	"github.com/tomcz/s3backup/client/store"
	"github.com/tomcz/s3backup/config"
)

var (
	symKey        string
	pemKeyFile    string
	awsAccessKey  string
	awsSecretKey  string
	awsToken      string
	awsRegion     string
	awsEndpoint   string
	vaultRoleID   string
	vaultSecretID string
	vaultToken    string
	vaultPath     string
	vaultAddr     string
	vaultCaCert   string
	skipHash      bool
)

func main() {
	var cmdVersion = &cobra.Command{
		Use:   "version",
		Short: "Print version and exit",
		Run:   printVersion,
	}
	var cmdBasicPut = &cobra.Command{
		Use:   "put s3://bucket/objectkey local_file_path",
		Short: "Put local file to S3 bucket using local credentials",
		Args:  cobra.ExactArgs(2),
		RunE:  basicPut,
	}
	var cmdBasicGet = &cobra.Command{
		Use:   "get s3://bucket/objectkey local_file_path",
		Short: "Get local file from S3 bucket using local credentials",
		Args:  cobra.ExactArgs(2),
		RunE:  basicGet,
	}
	var cmdVaultPut = &cobra.Command{
		Use:   "vault-put s3://bucket/objectkey local_file_path",
		Short: "Put local file to S3 bucket using credentials from vault",
		Args:  cobra.ExactArgs(2),
		RunE:  vaultPut,
	}
	var cmdVaultGet = &cobra.Command{
		Use:   "vault-get s3://bucket/objectkey local_file_path",
		Short: "Get local file from S3 bucket using credentials from vault",
		Args:  cobra.ExactArgs(2),
		RunE:  vaultGet,
	}
	var rootCmd = &cobra.Command{Use: "s3backup"}
	rootCmd.AddCommand(
		cmdVersion,
		basicFlags(cmdBasicPut),
		basicFlags(cmdBasicGet),
		vaultFlags(cmdVaultPut),
		vaultFlags(cmdVaultGet),
	)
	if err := rootCmd.Execute(); err != nil {
		log.Fatalln(err)
	}
}

func basicFlags(cmd *cobra.Command) *cobra.Command {
	flags := cmd.Flags()
	flags.StringVar(&symKey, "symKey", "", "Base64-encoded 256-bit symmetric AES key (optional)")
	flags.StringVar(&pemKeyFile, "pemKey", "", "Path to PEM-encoded public or private key file (optional)")
	flags.StringVar(&awsAccessKey, "accessKey", "", "AWS Access Key ID (if not using default AWS credentials)")
	flags.StringVar(&awsSecretKey, "secretKey", "", "AWS Secret Key (required when accessKey is provided)")
	flags.StringVar(&awsToken, "token", "", "AWS Token (effective only when accessKey is provided, depends on your AWS setup)")
	// have seen too many failures when AWS region was not set, so we set it to a somewhat sensible default
	flags.StringVar(&awsRegion, "region", "us-east-1", "AWS Region, override when necessary")
	flags.StringVar(&awsEndpoint, "endpoint", "", "Custom AWS Endpoint (optional)")
	flags.BoolVar(&skipHash, "nocheck", false, "Do not create or verify backup checksums")
	return cmd
}

func vaultFlags(cmd *cobra.Command) *cobra.Command {
	flags := cmd.Flags()
	flags.StringVar(&vaultRoleID, "role", "", "Vault role_id to retrieve backup credentials (either role & secret, or token)")
	flags.StringVar(&vaultSecretID, "secret", "", "Vault secret_id to retrieve backup credentials (either role & secret, or token)")
	flags.StringVar(&vaultToken, "token", "", "Vault token to retrieve backup credentials (either role & secret, or token)")
	flags.StringVar(&vaultPath, "path", "", "Vault secret path containing backup credentials (required)")
	flags.StringVar(&vaultCaCert, "caCert", "", "Vault root certificate file (optional)")
	flags.StringVar(&vaultAddr, "vault", "", "Vault service address (required)")
	flags.BoolVar(&skipHash, "nocheck", false, "Do not create or verify backup checksums")
	return cmd
}

func printVersion(_ *cobra.Command, _ []string) {
	fmt.Println(config.Commit())
}

func basicPut(_ *cobra.Command, args []string) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	return c.PutLocalFile(args[0], args[1])
}

func basicGet(_ *cobra.Command, args []string) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	return c.GetRemoteFile(args[0], args[1])
}

func vaultPut(cmd *cobra.Command, args []string) error {
	if err := initWithVault(); err != nil {
		return err
	}
	return basicPut(cmd, args)
}

func vaultGet(cmd *cobra.Command, args []string) error {
	if err := initWithVault(); err != nil {
		return err
	}
	return basicGet(cmd, args)
}

func initWithVault() error {
	log.Println("Fetching configuration from vault")

	if vaultPath == "" {
		return errors.New("vault secret path not provided")
	}

	var err error
	var cfg *config.Config
	if vaultToken != "" {
		cfg, err = config.LookupWithToken(vaultAddr, vaultCaCert, vaultToken, vaultPath)
	} else if vaultRoleID != "" && vaultSecretID != "" {
		cfg, err = config.LookupWithAppRole(vaultAddr, vaultCaCert, vaultRoleID, vaultSecretID, vaultPath)
	} else {
		err = errors.New("vault credentials not provided")
	}
	if err != nil {
		return err
	}

	symKey = cfg.CipherKey
	awsAccessKey = cfg.S3AccessKey
	awsSecretKey = cfg.S3SecretKey
	awsToken = cfg.S3Token
	awsRegion = cfg.S3Region
	awsEndpoint = cfg.S3Endpoint

	return nil
}

func newClient() (*client.Client, error) {
	s3, err := store.NewS3(
		awsAccessKey,
		awsSecretKey,
		awsToken,
		awsRegion,
		awsEndpoint,
	)
	if err != nil {
		return nil, err
	}
	var cipher client.Cipher
	if symKey != "" {
		cipher, err = crypto.NewAESCipher(symKey)
	}
	if pemKeyFile != "" {
		cipher, err = crypto.NewRSACipher(pemKeyFile)
	}
	if err != nil {
		return nil, err
	}
	var hash client.Hash
	if !skipHash {
		hash = crypto.NewHash()
	}
	return &client.Client{
		Hash:   hash,
		Cipher: cipher,
		Store:  s3,
	}, nil
}
