package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/urfave/cli/v2"

	"github.com/tomcz/s3backup/v2/internal/client"
	"github.com/tomcz/s3backup/v2/internal/client/crypto"
	"github.com/tomcz/s3backup/v2/internal/client/store"
	"github.com/tomcz/s3backup/v2/internal/config"
	"github.com/tomcz/s3backup/v2/internal/utils"
)

// build information
var (
	commit string
	tag    string
)

// command line flags
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
	rsaPrivKey    string
	rsaPubKey     string
)

// command line args
var (
	remotePath string
	localPath  string
	inFile     string
	outFile    string
)

func main() {
	cmdVersion := &cli.Command{
		Name:   "version",
		Usage:  "Print version and exit",
		Action: printVersion,
	}
	cmdBasicPut := &cli.Command{
		Name:      "put",
		Usage:     "Upload file to S3 bucket using local credentials",
		ArgsUsage: "local_file_path s3://bucket/objectkey",
		Before:    setLocalRemote,
		Action:    basicPut,
		Flags:     basicFlags(true),
	}
	cmdBasicGet := &cli.Command{
		Name:      "get",
		Usage:     "Download file from S3 bucket using local credentials",
		ArgsUsage: "s3://bucket/objectkey local_file_path",
		Before:    setLocalRemote,
		Action:    basicGet,
		Flags:     basicFlags(false),
	}
	cmdVaultPut := &cli.Command{
		Name:      "vault-put",
		Usage:     "Upload file to S3 bucket using credentials from vault",
		ArgsUsage: "local_file_path s3://bucket/objectkey",
		Before:    setLocalRemote,
		Action:    vaultPut,
		Flags:     vaultFlags(true),
	}
	cmdVaultGet := &cli.Command{
		Name:      "vault-get",
		Usage:     "Download file from S3 bucket using credentials from vault",
		ArgsUsage: "s3://bucket/objectkey local_file_path",
		Before:    setLocalRemote,
		Action:    vaultGet,
		Flags:     vaultFlags(false),
	}
	cmdGenAES := &cli.Command{
		Name:   "aes",
		Usage:  "Generate and print AES key",
		Action: genSecretKey,
	}
	cmdGenRSA := &cli.Command{
		Name:   "rsa",
		Usage:  "Generate RSA key pair files",
		Action: genKeyPair,
		Flags:  genKeyFlags(),
	}
	cmdKeygen := &cli.Command{
		Name:        "keygen",
		Usage:       "Generate RSA and AES backup keys",
		Subcommands: []*cli.Command{cmdGenAES, cmdGenRSA},
	}
	cmdEncrypt := &cli.Command{
		Name:      "encrypt",
		Usage:     "Encrypt a local file",
		ArgsUsage: "inFile outFile",
		Before:    setInOutFiles,
		Action:    encryptLocalFile,
		Flags:     cipherFlags(true),
	}
	cmdDecrypt := &cli.Command{
		Name:      "decrypt",
		Usage:     "Decrypt a local file",
		ArgsUsage: "inFile outFile",
		Before:    setInOutFiles,
		Action:    decryptLocalFile,
		Flags:     cipherFlags(false),
	}
	app := &cli.App{
		Name:    "s3backup",
		Usage:   "S3 backup script in a single binary",
		Version: version(),
		Commands: []*cli.Command{
			cmdVersion,
			cmdBasicPut,
			cmdBasicGet,
			cmdVaultPut,
			cmdVaultGet,
			cmdKeygen,
			cmdEncrypt,
			cmdDecrypt,
		},
	}
	if err := app.Run(os.Args); err != nil {
		log.Fatalln(err)
	}
}

func basicFlags(encrypt bool) []cli.Flag {
	sym := "decryption"
	asym := "private"
	check := "verify"
	if encrypt {
		sym = "encryption"
		asym = "public"
		check = "create"
	}
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "symKey",
			Usage:       fmt.Sprintf("Password to use for symmetric AES %s (optional)", sym),
			Destination: &symKey,
		},
		&cli.StringFlag{
			Name:        "pemKey",
			Usage:       fmt.Sprintf("Path to PEM-encoded %s key `FILE` (optional)", asym),
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
		&cli.StringFlag{
			Name:        "region",
			Usage:       "AWS Region (we use AWS defaults if not provided)",
			Destination: &awsRegion,
		},
		&cli.StringFlag{
			Name:        "endpoint",
			Usage:       "Custom AWS Endpoint `URL` (optional)",
			Destination: &awsEndpoint,
		},
		&cli.BoolFlag{
			Name:        "nocheck",
			Usage:       fmt.Sprintf("Do not %s backup checksums", check),
			Destination: &skipHash,
		},
	}
}

func cipherFlags(encrypt bool) []cli.Flag {
	sym := "decryption"
	asym := "private"
	if encrypt {
		sym = "encryption"
		asym = "public"
	}
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "symKey",
			Usage:       fmt.Sprintf("Password to use for symmetric AES %s", sym),
			Destination: &symKey,
		},
		&cli.StringFlag{
			Name:        "pemKey",
			Usage:       fmt.Sprintf("Path to PEM-encoded %s key `FILE`", asym),
			Destination: &pemKeyFile,
		},
	}
}

func vaultFlags(encrypt bool) []cli.Flag {
	check := "verify"
	if encrypt {
		check = "create"
	}
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
			Usage:       fmt.Sprintf("Do not %s backup checksums", check),
			Destination: &skipHash,
		},
	}
}

func genKeyFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "priv",
			Usage:       "Private key `FILE` for RSA key pair",
			Value:       "private.pem",
			Destination: &rsaPrivKey,
		},
		&cli.StringFlag{
			Name:        "pub",
			Usage:       "Public key `FILE` for RSA key pair",
			Value:       "public.pem",
			Destination: &rsaPubKey,
		},
	}
}

func version() string {
	return fmt.Sprintf("%s (%s)", tag, commit)
}

func printVersion(*cli.Context) error {
	fmt.Println(version())
	return nil
}

func setLocalRemote(c *cli.Context) error {
	if c.NArg() != 2 {
		return errors.New("remote path & local path are required")
	}
	args := c.Args()
	localPath = args.Get(0)
	remotePath = args.Get(1)
	return checkPaths()
}

func checkPaths() error {
	if store.IsRemote(remotePath) && store.IsRemote(localPath) {
		return errors.New("cannot have two remote paths")
	}
	if !store.IsRemote(remotePath) && !store.IsRemote(localPath) {
		return errors.New("cannot have two local paths")
	}
	if store.IsRemote(localPath) {
		localPath, remotePath = remotePath, localPath
	}
	return nil
}

func basicPut(*cli.Context) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	return c.PutLocalFile(remotePath, localPath)
}

func basicGet(*cli.Context) error {
	c, err := newClient()
	if err != nil {
		return err
	}
	return c.GetRemoteFile(remotePath, localPath)
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
	cipher, err := optionalCipher()
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

func vaultPut(c *cli.Context) error {
	if err := initWithVault(true); err != nil {
		return err
	}
	defer maybeRemoveKeyFile()
	return basicPut(c)
}

func vaultGet(c *cli.Context) error {
	if err := initWithVault(false); err != nil {
		return err
	}
	defer maybeRemoveKeyFile()
	return basicGet(c)
}

func maybeRemoveKeyFile() {
	if pemKeyFile != "" {
		if err := os.Remove(pemKeyFile); err != nil {
			log.Printf("WARNING: unable to remove key file %s: %v\n", pemKeyFile, err)
		}
	}
}

func initWithVault(encrypt bool) error {
	cfg, err := configFromVault()
	if err != nil {
		return err
	}
	if encrypt && cfg.PublicKey != "" {
		pemKeyFile, err = utils.CreateTempFile("pub", []byte(cfg.PublicKey))
		if err != nil {
			return err
		}
	}
	if !encrypt && cfg.PrivateKey != "" {
		pemKeyFile, err = utils.CreateTempFile("prv", []byte(cfg.PrivateKey))
		if err != nil {
			return err
		}
	}
	symKey = cfg.CipherKey
	awsAccessKey = cfg.S3AccessKey
	awsSecretKey = cfg.S3SecretKey
	awsToken = cfg.S3Token
	awsRegion = cfg.S3Region
	awsEndpoint = cfg.S3Endpoint
	return nil
}

func configFromVault() (*config.Config, error) {
	log.Println("Fetching configuration from vault")
	if vaultPath == "" {
		return nil, errors.New("vault secret path not provided")
	}
	ctx := context.Background()
	if vaultToken != "" {
		return config.LookupWithToken(ctx, vaultAddr, vaultCaCert, vaultToken, vaultPath)
	}
	if vaultRoleID != "" && vaultSecretID != "" {
		return config.LookupWithAppRole(ctx, vaultAddr, vaultCaCert, vaultRoleID, vaultSecretID, vaultPath)
	}
	return nil, errors.New("vault credentials not provided")
}

func genSecretKey(*cli.Context) error {
	key, err := crypto.GenerateAESKeyString()
	if err != nil {
		return err
	}
	fmt.Println(key)
	return nil
}

func genKeyPair(*cli.Context) error {
	return crypto.GenerateRSAKeyPair(rsaPrivKey, rsaPubKey)
}

func setInOutFiles(c *cli.Context) error {
	if c.NArg() != 2 {
		return errors.New("in and out files are required")
	}
	args := c.Args()
	inFile = args.Get(0)
	outFile = args.Get(1)
	return nil
}

func encryptLocalFile(*cli.Context) error {
	cipher, err := requiredCipher()
	if err != nil {
		return err
	}
	return cipher.Encrypt(inFile, outFile)
}

func decryptLocalFile(*cli.Context) error {
	cipher, err := requiredCipher()
	if err != nil {
		return err
	}
	return cipher.Decrypt(inFile, outFile)
}

func optionalCipher() (client.Cipher, error) {
	if symKey != "" {
		return crypto.NewAESCipher(symKey)
	}
	if pemKeyFile != "" {
		return crypto.NewRSACipher(pemKeyFile)
	}
	return nil, nil
}

func requiredCipher() (client.Cipher, error) {
	cipher, err := optionalCipher()
	if err != nil || cipher != nil {
		return cipher, err
	}
	return nil, errors.New("either one of symKey or pemKey is required")
}
