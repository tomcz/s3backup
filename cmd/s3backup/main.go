package main

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v2"

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
	var cmdVersion = &cli.Command{
		Name:   "version",
		Usage:  "Print version and exit",
		Action: printVersion,
	}
	var cmdBasicPut = &cli.Command{
		Name:      "put",
		Usage:     "Put local file to S3 bucket using local credentials",
		ArgsUsage: "s3://bucket/objectkey local_file_path",
		Action:    basicPut,
		Flags:     basicFlags(),
	}
	var cmdBasicGet = &cli.Command{
		Name:      "get",
		Usage:     "Get local file from S3 bucket using local credentials",
		ArgsUsage: "s3://bucket/objectkey local_file_path",
		Action:    basicGet,
		Flags:     basicFlags(),
	}
	var cmdVaultPut = &cli.Command{
		Name:      "vault-put",
		Usage:     "Put local file to S3 bucket using credentials from vault",
		ArgsUsage: "s3://bucket/objectkey local_file_path",
		Action:    vaultPut,
		Flags:     vaultFlags(),
	}
	var cmdVaultGet = &cli.Command{
		Name:      "vault-get",
		Usage:     "Get local file from S3 bucket using credentials from vault",
		ArgsUsage: "s3://bucket/objectkey local_file_path",
		Action:    vaultGet,
		Flags:     vaultFlags(),
	}
	app := &cli.App{
		Name:    "s3backup",
		Usage:   "S3 backup script in a single binary",
		Version: config.Version(),
		Commands: []*cli.Command{
			cmdVersion,
			cmdBasicPut,
			cmdBasicGet,
			cmdVaultPut,
			cmdVaultGet,
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatalln(err)
	}
}

func basicFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "symKey",
			Usage:       "Base64-encoded 256-bit symmetric AES key (optional)",
			Destination: &symKey,
		},
		&cli.StringFlag{
			Name:        "pemKey",
			Usage:       "Path to PEM-encoded public or private key `FILE` (optional)",
			Destination: &pemKeyFile,
		},
		&cli.StringFlag{
			Name:        "accessKey",
			Usage:       "AWS Access Key ID (if not using default AWS credentials)",
			Destination: &awsAccessKey,
		},
		&cli.StringFlag{
			Name:        "secretKey",
			Usage:       "AWS Secret Key (required when accessKey is provided)",
			Destination: &awsSecretKey,
		},
		&cli.StringFlag{
			Name:        "token",
			Usage:       "AWS Token (effective only when accessKey is provided, depends on your AWS setup)",
			Destination: &awsToken,
		},
		// have seen too many failures when AWS region was not set, so we set it to a somewhat sensible default
		&cli.StringFlag{
			Name:        "region",
			Usage:       "AWS Region, override when necessary",
			Value:       "us-east-1",
			Destination: &awsRegion,
		},
		&cli.StringFlag{
			Name:        "endpoint",
			Usage:       "Custom AWS Endpoint `URL` (optional)",
			Destination: &awsEndpoint,
		},
		&cli.BoolFlag{
			Name:        "nocheck",
			Usage:       "Do not create or verify backup checksums",
			Destination: &skipHash,
		},
	}
}

func vaultFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "role",
			Usage:       "Vault role_id to retrieve backup credentials (either role & secret, or token)",
			Destination: &vaultRoleID,
		},
		&cli.StringFlag{
			Name:        "secret",
			Usage:       "Vault secret_id to retrieve backup credentials (either role & secret, or token)",
			Destination: &vaultSecretID,
		},
		&cli.StringFlag{
			Name:        "token",
			Usage:       "Vault token to retrieve backup credentials (either role & secret, or token)",
			Destination: &vaultToken,
		},
		&cli.StringFlag{
			Name:        "path",
			Usage:       "Vault secret path containing backup credentials (required)",
			Required:    true,
			Destination: &vaultPath,
		},
		&cli.StringFlag{
			Name:        "caCert",
			Usage:       "Vault root certificate `FILE` (optional)",
			Destination: &vaultCaCert,
		},
		&cli.StringFlag{
			Name:        "vault",
			Usage:       "Vault service `URL` (required)",
			Required:    true,
			Destination: &vaultAddr,
		},
		&cli.BoolFlag{
			Name:        "nocheck",
			Usage:       "Do not create or verify backup checksums",
			Destination: &skipHash,
		},
	}
}

func printVersion(*cli.Context) error {
	fmt.Println(config.Version())
	return nil
}

func basicPut(ctx *cli.Context) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	if ctx.NArg() != 2 {
		return errors.New("remote path & local path are required")
	}
	args := ctx.Args()
	return c.PutLocalFile(args.Get(0), args.Get(1))
}

func basicGet(ctx *cli.Context) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	if ctx.NArg() != 2 {
		return errors.New("remote path & local path are required")
	}
	args := ctx.Args()
	return c.GetRemoteFile(args.Get(0), args.Get(1))
}

func vaultPut(ctx *cli.Context) error {
	if err := initWithVault(); err != nil {
		return err
	}
	return basicPut(ctx)
}

func vaultGet(ctx *cli.Context) error {
	if err := initWithVault(); err != nil {
		return err
	}
	return basicGet(ctx)
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
