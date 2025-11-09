package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"
	"slices"

	"github.com/AlecAivazis/survey/v2"
	"github.com/urfave/cli-altsrc/v3"
	"github.com/urfave/cli-altsrc/v3/yaml"
	"github.com/urfave/cli/v3"

	"github.com/tomcz/s3backup/v2/internal/client"
	"github.com/tomcz/s3backup/v2/internal/client/crypto"
	"github.com/tomcz/s3backup/v2/internal/client/store"
	"github.com/tomcz/s3backup/v2/internal/config"
)

// build information
var (
	commit string
	tag    string
)

// from S3BACKUP_YAML env var
var configFile string

// cipher flags
var (
	useOldPass  bool
	symKeyValue string
	pemKeyFile  string
)

// get & put flags
var (
	skipHash bool

	awsAccessKey string
	awsSecretKey string
	awsToken     string
	awsRegion    string
	awsEndpoint  string

	vaultPath     string
	vaultIsKV2    bool
	vaultMount    string
	vaultRoleID   string
	vaultSecretID string
	vaultToken    string
	vaultAddress  string
	vaultCaCert   string
)

// get & put args
var (
	remotePath string
	localPath  string
)

// encrypt & decrypt args
var (
	inFile  string
	outFile string
)

func main() {
	configFile = os.Getenv("S3BACKUP_YAML")
	if configFile != "" {
		log.Println("Loading defaults from", configFile)
	}
	cmdVersion := &cli.Command{
		Name:   "version",
		Usage:  "Print version and exit",
		Action: printVersion,
	}
	cmdBasicPut := &cli.Command{
		Name:      "put",
		Usage:     "Upload file to S3 bucket using local credentials",
		Arguments: putArgs(),
		Action:    basicPut,
		Flags:     basicFlags(true),
	}
	cmdBasicGet := &cli.Command{
		Name:      "get",
		Usage:     "Download file from S3 bucket using local credentials",
		Arguments: getArgs(),
		Action:    basicGet,
		Flags:     basicFlags(false),
	}
	cmdVaultPut := &cli.Command{
		Name:      "vault-put",
		Usage:     "Upload file to S3 bucket using credentials from vault",
		Arguments: putArgs(),
		Action:    vaultPut,
		Flags:     vaultFlags(true),
	}
	cmdVaultGet := &cli.Command{
		Name:      "vault-get",
		Usage:     "Download file from S3 bucket using credentials from vault",
		Arguments: putArgs(),
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
		Name:     "keygen",
		Usage:    "Generate RSA and AES backup keys",
		Commands: []*cli.Command{cmdGenAES, cmdGenRSA},
	}
	cmdEncrypt := &cli.Command{
		Name:      "encrypt",
		Usage:     "Encrypt a local file",
		Arguments: inOutArgs(),
		Action:    encryptLocalFile,
		Flags:     cipherFlags(true),
	}
	cmdDecrypt := &cli.Command{
		Name:      "decrypt",
		Usage:     "Decrypt a local file",
		Arguments: inOutArgs(),
		Action:    decryptLocalFile,
		Flags:     cipherFlags(false),
	}
	app := &cli.Command{
		Name:    "s3backup",
		Usage:   "S3 backup script in a single binary",
		Version: version(),
		Commands: []*cli.Command{
			cmdBasicPut,
			cmdBasicGet,
			cmdVaultPut,
			cmdVaultGet,
			cmdKeygen,
			cmdEncrypt,
			cmdDecrypt,
			cmdVersion,
		},
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := app.Run(ctx, os.Args); err != nil {
		log.Fatalln(err)
	}
}

// ============================================================
// CLI flags
// ============================================================

func maybeFromEnvOrYaml(yamlKey string, envVars ...string) cli.ValueSourceChain {
	var sources []cli.ValueSource
	for _, envVar := range envVars {
		sources = append(sources, cli.EnvVar(envVar))
	}
	if configFile != "" {
		sources = append(sources, yaml.YAML(yamlKey, altsrc.StringSourcer(configFile)))
	}
	if len(sources) > 0 {
		return cli.NewValueSourceChain(sources...)
	}
	return cli.ValueSourceChain{}
}

func cipherFlags(encrypt bool) []cli.Flag {
	sym := "decryption"
	asym := "private"
	if encrypt {
		sym = "encryption"
		asym = "public"
	}
	flags := []cli.Flag{
		&cli.StringFlag{
			Name:        "symKey",
			Aliases:     []string{"sym"},
			Usage:       fmt.Sprintf("Password or base64-encoded key to use for symmetric AES %s; use \"ask\" to provide it via an interactive prompt", sym),
			Destination: &symKeyValue,
			Sources:     maybeFromEnvOrYaml("symKey"),
		},
		&cli.StringFlag{
			Name:        "pemKey",
			Aliases:     []string{"pem"},
			Usage:       fmt.Sprintf("Path to PEM-encoded %s key `FILE`", asym),
			Destination: &pemKeyFile,
			Sources:     maybeFromEnvOrYaml("pemKey"),
		},
	}
	if encrypt {
		extras := []cli.Flag{
			&cli.BoolFlag{
				Name:        "oldPass",
				Aliases:     []string{"old", "o"},
				Usage:       "Maintain password compatibility with older s3backup releases",
				Destination: &useOldPass,
				Sources:     maybeFromEnvOrYaml("oldPass"),
			},
		}
		flags = slices.Concat(extras, flags)
	}
	return flags
}

func basicFlags(encrypt bool) []cli.Flag {
	check := "verify"
	if encrypt {
		check = "create"
	}
	flags := []cli.Flag{
		&cli.StringFlag{
			Name:        "accessKey",
			Usage:       "AWS Access Key ID (if not using default AWS credentials)",
			Destination: &awsAccessKey,
			Sources:     maybeFromEnvOrYaml("accessKey"),
		},
		&cli.StringFlag{
			Name:        "secretKey",
			Usage:       "AWS Secret Key (required when accessKey is provided)",
			Destination: &awsSecretKey,
			Sources:     maybeFromEnvOrYaml("secretKey"),
		},
		&cli.StringFlag{
			Name:        "token",
			Usage:       "AWS Token (effective only when accessKey is provided, depends on your AWS setup)",
			Destination: &awsToken,
			Sources:     maybeFromEnvOrYaml("token"),
		},
		&cli.StringFlag{
			Name:        "region",
			Usage:       "AWS Region (we use AWS defaults if not provided)",
			Destination: &awsRegion,
			Sources:     maybeFromEnvOrYaml("region"),
		},
		&cli.StringFlag{
			Name:        "endpoint",
			Usage:       "Custom AWS Endpoint `URL` (optional)",
			Destination: &awsEndpoint,
			Sources:     maybeFromEnvOrYaml("endpoint"),
		},
		&cli.BoolFlag{
			Name:        "nocheck",
			Usage:       fmt.Sprintf("Do not %s backup checksums", check),
			Destination: &skipHash,
			Sources:     maybeFromEnvOrYaml("nocheck"),
		},
	}
	return slices.Concat(cipherFlags(encrypt), flags)
}

func vaultFlags(encrypt bool) []cli.Flag {
	check := "verify"
	if encrypt {
		check = "create"
	}
	return []cli.Flag{
		&cli.StringFlag{
			Name:        "path",
			Usage:       "Vault secret path containing backup credentials (required)",
			Required:    true,
			Destination: &vaultPath,
			Sources:     maybeFromEnvOrYaml("path"),
		},
		&cli.BoolFlag{
			Name:        "kv2",
			Usage:       "Vault secret path represents a key/value version 2 secrets engine",
			Destination: &vaultIsKV2,
			Sources:     maybeFromEnvOrYaml("kv2"),
		},
		&cli.StringFlag{
			Name:        "mount",
			Usage:       "Vault approle mount path (default: approle)",
			Destination: &vaultMount,
			Sources:     maybeFromEnvOrYaml("mount"),
		},
		&cli.StringFlag{
			Name:        "role",
			Usage:       "Vault role_id to retrieve backup credentials (either role & secret, or token)",
			Destination: &vaultRoleID,
			Sources:     maybeFromEnvOrYaml("role", "VAULT_ROLE_ID"),
		},
		&cli.StringFlag{
			Name:        "secret",
			Usage:       "Vault secret_id to retrieve backup credentials (either role & secret, or token)",
			Destination: &vaultSecretID,
			Sources:     maybeFromEnvOrYaml("secret", "VAULT_SECRET_ID"),
		},
		&cli.StringFlag{
			Name:        "token",
			Usage:       "Vault token to retrieve backup credentials (either role & secret, or token)",
			Destination: &vaultToken,
			Sources:     maybeFromEnvOrYaml("token", "VAULT_TOKEN"),
		},
		&cli.StringFlag{
			Name:        "caCert",
			Usage:       "Vault root certificate `FILE` (optional, or use one of VAULT_CACERT, VAULT_CACERT_BYTES, VAULT_CAPATH env vars)",
			Destination: &vaultCaCert,
			Sources:     maybeFromEnvOrYaml("caCert"),
		},
		&cli.StringFlag{
			Name:        "vault",
			Usage:       "Vault service `URL` (or use VAULT_ADDR env var)",
			Destination: &vaultAddress,
			Sources:     maybeFromEnvOrYaml("vault"),
		},
		&cli.BoolFlag{
			Name:        "nocheck",
			Usage:       fmt.Sprintf("Do not %s backup checksums", check),
			Destination: &skipHash,
			Sources:     maybeFromEnvOrYaml("nocheck"),
		},
	}
}

func genKeyFlags() []cli.Flag {
	return []cli.Flag{
		&cli.StringFlag{
			Name:  "priv",
			Usage: "Private key `FILE` for RSA key pair",
			Value: "private.pem",
		},
		&cli.StringFlag{
			Name:  "pub",
			Usage: "Public key `FILE` for RSA key pair",
			Value: "public.pem",
		},
	}
}

// ============================================================
// CLI args
// ============================================================

func putArgs() []cli.Argument {
	return []cli.Argument{
		&cli.StringArg{
			Name:        "local-path",
			UsageText:   "local_file_path",
			Config:      cli.StringConfig{TrimSpace: true},
			Destination: &localPath,
		},
		&cli.StringArg{
			Name:        "remote-path",
			UsageText:   "s3://bucket/objectkey",
			Config:      cli.StringConfig{TrimSpace: true},
			Destination: &remotePath,
		},
	}
}

func getArgs() []cli.Argument {
	return []cli.Argument{
		&cli.StringArg{
			Name:        "remote-path",
			UsageText:   "s3://bucket/objectkey",
			Config:      cli.StringConfig{TrimSpace: true},
			Destination: &remotePath,
		},
		&cli.StringArg{
			Name:        "local-path",
			UsageText:   "local_file_path",
			Config:      cli.StringConfig{TrimSpace: true},
			Destination: &localPath,
		},
	}
}

func inOutArgs() []cli.Argument {
	return []cli.Argument{
		&cli.StringArg{
			Name:        "in-file",
			UsageText:   "input_file_path",
			Config:      cli.StringConfig{TrimSpace: true},
			Destination: &inFile,
		},
		&cli.StringArg{
			Name:        "out-file",
			UsageText:   "output_file_path",
			Config:      cli.StringConfig{TrimSpace: true},
			Destination: &outFile,
		},
	}
}

// ============================================================
// CLI commands
// ============================================================

func printVersion(context.Context, *cli.Command) error {
	fmt.Println(version())
	return nil
}

func basicPut(ctx context.Context, _ *cli.Command) error {
	remote, local, err := checkPaths(remotePath, localPath)
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	return c.PutLocalFile(ctx, remote, local)
}

func basicGet(ctx context.Context, _ *cli.Command) error {
	remote, local, err := checkPaths(remotePath, localPath)
	if err != nil {
		return err
	}
	c, err := newClient()
	if err != nil {
		return err
	}
	return c.GetRemoteFile(ctx, remote, local)
}

func vaultPut(ctx context.Context, _ *cli.Command) error {
	if err := initWithVault(ctx, true); err != nil {
		return err
	}
	defer removePemKeyFile(pemKeyFile)
	return basicPut(ctx, nil)
}

func vaultGet(ctx context.Context, _ *cli.Command) error {
	if err := initWithVault(ctx, false); err != nil {
		return err
	}
	defer removePemKeyFile(pemKeyFile)
	return basicGet(ctx, nil)
}

func genSecretKey(context.Context, *cli.Command) error {
	fmt.Println(crypto.GenerateAESKeyString())
	return nil
}

func genKeyPair(_ context.Context, cmd *cli.Command) error {
	return crypto.GenerateRSAKeyPair(cmd.String("priv"), cmd.String("pub"))
}

func encryptLocalFile(context.Context, *cli.Command) error {
	if err := checkInOutFiles(inFile, outFile); err != nil {
		return err
	}
	cipher, err := requiredCipher()
	if err != nil {
		return err
	}
	return cipher.Encrypt(inFile, outFile)
}

func decryptLocalFile(context.Context, *cli.Command) error {
	if err := checkInOutFiles(inFile, outFile); err != nil {
		return err
	}
	cipher, err := requiredCipher()
	if err != nil {
		return err
	}
	return cipher.Decrypt(inFile, outFile)
}

// ============================================================
// Common actions
// ============================================================

func version() string {
	if tag != "" && commit != "" {
		return fmt.Sprintf("%s (%s)", tag, commit)
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				return setting.Value
			}
		}
	}
	return "unknown"
}

func checkPaths(inRemote, inLocal string) (outRemote string, outLocal string, err error) {
	if inRemote == "" || inLocal == "" {
		err = errors.New("need both local and remote paths")
		return
	}
	if store.IsRemote(inRemote) && store.IsRemote(inLocal) {
		err = errors.New("cannot have two remote paths")
		return
	}
	if !store.IsRemote(inRemote) && !store.IsRemote(inLocal) {
		err = errors.New("cannot have two local paths")
		return
	}
	if store.IsRemote(inLocal) {
		outRemote = inLocal
		outLocal = inRemote
		return
	}
	outLocal = inLocal
	outRemote = inRemote
	return
}

func checkInOutFiles(inputFile, outputFile string) error {
	if inputFile == "" || outputFile == "" {
		return errors.New("need both input and output files")
	}
	return nil
}

func newClient() (*client.Client, error) {
	aws := store.AwsS3{
		AccessKey: awsAccessKey,
		SecretKey: awsSecretKey,
		Token:     awsToken,
		Region:    awsRegion,
		Endpoint:  awsEndpoint,
	}
	backend, err := aws.Store()
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
		Store:  backend,
	}, nil
}

func optionalCipher() (client.Cipher, error) {
	if symKeyValue == "ask" {
		prompt := &survey.Password{Message: "Enter password or base64-encoded key:"}
		if err := survey.AskOne(prompt, &symKeyValue, survey.WithValidator(survey.Required)); err != nil {
			return nil, err
		}
	}
	if symKeyValue != "" {
		return crypto.NewAESCipher(symKeyValue, useOldPass)
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

func initWithVault(ctx context.Context, encrypt bool) error {
	cfg, err := configFromVault(ctx)
	if err != nil {
		return err
	}
	if encrypt && cfg.PublicKey != "" {
		pemKeyFile, err = createPemKeyFile("pub", cfg.PublicKey)
		if err != nil {
			return err
		}
	}
	if !encrypt && cfg.PrivateKey != "" {
		pemKeyFile, err = createPemKeyFile("prv", cfg.PrivateKey)
		if err != nil {
			return err
		}
	}
	symKeyValue = cfg.CipherKey
	useOldPass = cfg.UseOldPass
	awsAccessKey = cfg.S3AccessKey
	awsSecretKey = cfg.S3SecretKey
	awsToken = cfg.S3Token
	awsRegion = cfg.S3Region
	awsEndpoint = cfg.S3Endpoint
	return nil
}

func configFromVault(ctx context.Context) (*config.Config, error) {
	vault := config.Vault{
		Path:       vaultPath,
		IsKV2:      vaultIsKV2,
		Mount:      vaultMount,
		Token:      vaultToken,
		RoleID:     vaultRoleID,
		SecretID:   vaultSecretID,
		VaultAddr:  vaultAddress,
		CaCertFile: vaultCaCert,
	}
	return vault.Lookup(ctx)
}

func createPemKeyFile(pattern string, contents string) (string, error) {
	file, err := os.CreateTemp("", pattern)
	if err != nil {
		return "", err
	}
	defer file.Close()

	_, err = file.WriteString(contents)
	if err != nil {
		return "", err
	}
	return file.Name(), nil
}

func removePemKeyFile(keyFile string) {
	if keyFile != "" {
		if err := os.Remove(keyFile); err != nil {
			log.Printf("WARNING: unable to remove key file %s: %v\n", keyFile, err)
		}
	}
}
