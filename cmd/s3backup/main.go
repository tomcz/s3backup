package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime/debug"

	"github.com/AlecAivazis/survey/v2"
	"github.com/alecthomas/kong"

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

const description = `
S3 backup script in a single binary.

NOTE: Command flag values can optionally be retrieved from a JSON configuration file.
The path to this configuration file is provided at runtime by the S3BACKUP_JSON environment variable.
This JSON file should contain an object whose keys must match the command flags they are meant to configure.
`

type putFlags struct {
	LocalPath  string `arg:"" help:"Required local file path"`
	RemotePath string `arg:"" help:"Required s3 path (s3://bucket/objectkey)"`
	SkipHash   bool   `name:"nocheck" help:"Do not create backup checksums"`
}

type getFlags struct {
	RemotePath string `arg:"" help:"Required s3 path (s3://bucket/objectkey)"`
	LocalPath  string `arg:"" help:"Required local file path"`
	SkipHash   bool   `name:"nocheck" help:"Do not verify backup checksums"`
}

type encryptFlags struct {
	SymKey string `name:"symKey" placeholder:"value" help:"Password or base64-encoded key to use for symmetric AES encryption (Use 'ask' to enter a password or key via an interactive prompt)"`
	Derive bool   `help:"Use cryptographic key derivation from symKey passwords. Slower, but stronger and more secure keys"`
	PemKey string `name:"pemKey" placeholder:"FILE"  help:"Path to PEM-encoded public key file"`
}

type decryptFlags struct {
	SymKey string `name:"symKey" placeholder:"value" help:"Password or base64-encoded key to use for symmetric AES decryption (Use 'ask' to enter a password or key via an interactive prompt)"`
	Derive bool   `help:"Use cryptographic key derivation from symKey passwords. Slower, but stronger and more secure keys"`
	PemKey string `name:"pemKey" placeholder:"FILE"  help:"Path to PEM-encoded private key file"`
}

type awsFlags struct {
	AccessKey string `name:"accessKey" placeholder:"value" help:"AWS Access Key ID (if not using default AWS credentials)"`
	SecretKey string `name:"secretKey" placeholder:"value" help:"AWS Secret Key (required when accessKey is provided)"`
	Token     string `name:"token"     placeholder:"value" help:"AWS Token (effective only when accessKey is provided, depends on your AWS setup)"`
	Region    string `name:"region"    placeholder:"value" help:"AWS Region (we use AWS defaults if not provided)"`
	Endpoint  string `name:"endpoint"  placeholder:"URL"   help:"Custom AWS Endpoint URL (optional)"`
}

type vaultFlags struct {
	Path     string `name:"path"   placeholder:"value" help:"Vault secret path containing backup credentials (required)" required:""`
	IsKV2    bool   `name:"kv2"                        help:"Vault secret path represents a key/value version 2 secrets engine"`
	Mount    string `name:"mount"  placeholder:"value" help:"Vault approle mount path (default: approle)"`
	RoleID   string `name:"role"   placeholder:"value" help:"Vault approle role_id to retrieve backup credentials (either role & secret, or token are required)"   env:"VAULT_ROLE_ID"`
	SecretID string `name:"secret" placeholder:"value" help:"Vault approle secret_id to retrieve backup credentials (either role & secret, or token are required)" env:"VAULT_SECRET_ID"`
	Token    string `name:"token"  placeholder:"value" help:"Vault token to retrieve backup credentials (either role & secret, or token are required)"     env:"VAULT_TOKEN"`
	CaCert   string `name:"caCert" placeholder:"FILE"  help:"Vault Root CA certificate (optional, or use one of VAULT_CACERT, VAULT_CACERT_BYTES, VAULT_CAPATH env vars)"`
	Address  string `name:"vault"  placeholder:"URL"   help:"Vault service URL (or use VAULT_ADDR env var)"`
}

type putCommand struct {
	putFlags
	encryptFlags
	awsFlags
}

type getCommand struct {
	getFlags
	decryptFlags
	awsFlags
}

type vaultPutCommand struct {
	putFlags
	vaultFlags
}

type vaultGetCommand struct {
	getFlags
	vaultFlags
}

type encryptCommand struct {
	InputFile  string `arg:"" help:"File to encrypt"`
	OutputFile string `arg:"" help:"Encrypted file"`
	encryptFlags
}

type decryptCommand struct {
	InputFile  string `arg:"" help:"File to decrypt"`
	OutputFile string `arg:"" help:"Decrypted file"`
	decryptFlags
}

type genAesCommand struct{}

type genRsaCommand struct {
	PrivKey string `name:"priv" default:"private.pem" help:"Private key file of RSA key pair"`
	PubKey  string `name:"pub" default:"public.pem" help:"Public key file of RSA key pair"`
}

type keygenCommand struct {
	AES genAesCommand `cmd:"" help:"Generate and print AES key"`
	RSA genRsaCommand `cmd:"" help:"Generate RSA key pair files"`
}

type versionCommand struct{}

type appCfg struct {
	Put      putCommand      `cmd:"" help:"Upload file to S3 bucket using local AWS credentials"`
	Get      getCommand      `cmd:"" help:"Download file from S3 bucket using local AWS credentials"`
	VaultPut vaultPutCommand `cmd:"" help:"Upload file to S3 bucket using AWS credentials from Vault"`
	VaultGet vaultGetCommand `cmd:"" help:"Download file from S3 bucket using AWS credentials from Vault"`
	Keygen   keygenCommand   `cmd:"" help:"Generate RSA or AES backup keys"`
	Encrypt  encryptCommand  `cmd:"" help:"Encrypt a local file"`
	Decrypt  decryptCommand  `cmd:"" help:"Decrypt a local file"`
	Version  versionCommand  `cmd:"" help:"Print version and exit"`
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	opts := []kong.Option{
		kong.Description(description),
		kong.HelpOptions{Compact: true},
	}
	if file := os.Getenv("S3BACKUP_JSON"); file != "" {
		log.Println("Using configuration from", file)
		opts = append(opts, kong.Configuration(kong.JSON, file))
	}

	app := kong.Parse(&appCfg{}, opts...)
	app.BindTo(ctx, (*context.Context)(nil))
	if err := app.Run(); err != nil {
		log.Fatalln("Failed:", err)
	}
}

func (c *versionCommand) Run() error {
	if tag != "" && commit != "" {
		fmt.Printf("%s (%s)\n", tag, commit)
		return nil
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, setting := range info.Settings {
			if setting.Key == "vcs.revision" {
				fmt.Println(setting.Value)
				return nil
			}
		}
	}
	fmt.Println("unknown")
	return nil
}

func (c *putCommand) Run(ctx context.Context) error {
	co := cipherOpts{
		symKey: c.SymKey,
		pemKey: c.PemKey,
		derive: c.Derive,
	}
	app, err := newClient(c.awsFlags, co, c.SkipHash)
	if err != nil {
		return err
	}
	remote, local, err := checkPaths(c.RemotePath, c.LocalPath)
	if err != nil {
		return err
	}
	return app.PutLocalFile(ctx, remote, local)
}

func (c *getCommand) Run(ctx context.Context) error {
	co := cipherOpts{
		symKey: c.SymKey,
		pemKey: c.PemKey,
		derive: c.Derive,
	}
	app, err := newClient(c.awsFlags, co, c.SkipHash)
	if err != nil {
		return err
	}
	remote, local, err := checkPaths(c.RemotePath, c.LocalPath)
	if err != nil {
		return err
	}
	return app.GetRemoteFile(ctx, remote, local)
}

func (c *vaultPutCommand) Run(ctx context.Context) error {
	cfg, err := vaultConfig(ctx, c.vaultFlags)
	if err != nil {
		return err
	}
	var pubKeyFile string
	if cfg.PublicKey != "" {
		pubKeyFile, err = createPemKeyFile("pub", cfg.PublicKey)
		if err != nil {
			return err
		}
	}
	defer removePemKeyFile(pubKeyFile)

	cmd := &putCommand{
		putFlags: c.putFlags,
		awsFlags: awsConfig(cfg),
		encryptFlags: encryptFlags{
			SymKey: cfg.CipherKey,
			PemKey: pubKeyFile,
			Derive: cfg.DeriveKey,
		},
	}
	return cmd.Run(ctx)
}

func (c vaultGetCommand) Run(ctx context.Context) error {
	cfg, err := vaultConfig(ctx, c.vaultFlags)
	if err != nil {
		return err
	}
	var privKeyFile string
	if cfg.PrivateKey != "" {
		privKeyFile, err = createPemKeyFile("priv", cfg.PrivateKey)
		if err != nil {
			return err
		}
	}
	defer removePemKeyFile(privKeyFile)

	cmd := &getCommand{
		getFlags: c.getFlags,
		awsFlags: awsConfig(cfg),
		decryptFlags: decryptFlags{
			SymKey: cfg.CipherKey,
			PemKey: privKeyFile,
			Derive: cfg.DeriveKey,
		},
	}
	return cmd.Run(ctx)
}

func (c *genAesCommand) Run() error {
	fmt.Println(crypto.GenerateAESKeyString())
	return nil
}

func (c *genRsaCommand) Run() error {
	return crypto.GenerateRSAKeyPair(c.PrivKey, c.PubKey)
}

func (c *encryptCommand) Run() error {
	co := cipherOpts{
		symKey: c.SymKey,
		pemKey: c.PemKey,
		derive: c.Derive,
	}
	cipher, err := co.Cipher()
	if err != nil {
		return err
	}
	if cipher == nil {
		return errors.New("either one of symKey or pemKey is required")
	}
	return cipher.Encrypt(c.InputFile, c.OutputFile)
}

func (c *decryptCommand) Run() error {
	co := cipherOpts{
		symKey: c.SymKey,
		pemKey: c.PemKey,
		derive: c.Derive,
	}
	cipher, err := co.Cipher()
	if err != nil {
		return err
	}
	if cipher == nil {
		return errors.New("either one of symKey or pemKey is required")
	}
	return cipher.Decrypt(c.InputFile, c.OutputFile)
}

func newClient(af awsFlags, co cipherOpts, skipHash bool) (*client.Client, error) {
	aws := store.AwsS3{
		AccessKey: af.AccessKey,
		SecretKey: af.SecretKey,
		Token:     af.Token,
		Region:    af.Region,
		Endpoint:  af.Endpoint,
	}
	backend, err := aws.Store()
	if err != nil {
		return nil, err
	}
	cipher, err := co.Cipher()
	if err != nil {
		return nil, err
	}
	app := &client.Client{
		Cipher: cipher,
		Store:  backend,
	}
	if !skipHash {
		app.Hash = crypto.NewHash()
	}
	return app, nil
}

type cipherOpts struct {
	symKey string
	pemKey string
	derive bool
}

func (o cipherOpts) Cipher() (client.Cipher, error) {
	if o.symKey == "ask" {
		var err error
		o.symKey, err = askForSymKey()
		if err != nil {
			return nil, err
		}
		o.derive, err = askToDerive()
		if err != nil {
			return nil, err
		}
	}
	if o.symKey != "" && o.derive {
		return crypto.NewDerivedAESCipher(o.symKey), nil
	}
	if o.symKey != "" {
		return crypto.NewAESCipher(o.symKey)
	}
	if o.pemKey != "" {
		return crypto.NewRSACipher(o.pemKey)
	}
	return nil, nil
}

func askForSymKey() (symKey string, err error) {
	prompt := &survey.Password{Message: "Enter password or base64-encoded key:"}
	err = survey.AskOne(prompt, &symKey, survey.WithValidator(survey.Required))
	return
}

func askToDerive() (derive bool, err error) {
	prompt := &survey.Confirm{Message: "Derive AES key from password?", Default: true}
	err = survey.AskOne(prompt, &derive)
	return
}

func checkPaths(inRemote, inLocal string) (outRemote string, outLocal string, err error) {
	if store.IsRemote(inRemote) && store.IsRemote(inLocal) {
		err = errors.New("cannot have two remote paths")
		return
	}
	if !store.IsRemote(inRemote) && !store.IsRemote(inLocal) {
		err = errors.New("cannot have two local paths")
		return
	}
	outLocal = inLocal
	outRemote = inRemote
	if store.IsRemote(inLocal) {
		outRemote = inLocal
		outLocal = inRemote
	}
	return
}

func vaultConfig(ctx context.Context, f vaultFlags) (*config.Config, error) {
	vault := config.Vault{
		Path:       f.Path,
		IsKV2:      f.IsKV2,
		Mount:      f.Mount,
		Token:      f.Token,
		RoleID:     f.RoleID,
		SecretID:   f.SecretID,
		VaultAddr:  f.Address,
		CaCertFile: f.CaCert,
	}
	return vault.Lookup(ctx)
}

func awsConfig(cfg *config.Config) awsFlags {
	return awsFlags{
		AccessKey: cfg.S3AccessKey,
		SecretKey: cfg.S3SecretKey,
		Token:     cfg.S3Token,
		Region:    cfg.S3Region,
		Endpoint:  cfg.S3Endpoint,
	}
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

func removePemKeyFile(pemKeyFile string) {
	if pemKeyFile != "" {
		if err := os.Remove(pemKeyFile); err != nil {
			log.Printf("WARNING: unable to remove key file %s: %v\n", pemKeyFile, err)
		}
	}
}
