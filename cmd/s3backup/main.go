package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"os/signal"
	"runtime/debug"
	"strings"
	"syscall"

	"github.com/alecthomas/kong"
	kongyaml "github.com/alecthomas/kong-yaml"
	"golang.org/x/term"

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

type putArgs struct {
	LocalPath  string `arg:"" type:"existingfile" help:"Source file path"`
	RemotePath string `arg:"" name:"s3://bucket/objectkey" help:"Destination S3 path"`
}

type getArgs struct {
	RemotePath string `arg:"" name:"s3://bucket/objectkey" help:"Source S3 path"`
	LocalPath  string `arg:"" type:"path" help:"Destination file path"`
}

type configFlags struct {
	ConfigFile kong.ConfigFlag `short:"c" env:"S3BACKUP_YAML" placeholder:"FILE" help:"Path to a YAML configuration file"`
}

type encryptFlags struct {
	SymKey string `name:"symKey" aliases:"sym" help:"Password or base64-encoded key to use for symmetric AES encryption; use \"ask\" as the value to provide a password via an interactive prompt"`
	PemKey string `name:"pemKey" aliases:"pem" placeholder:"FILE" type:"existingfile" help:"Path to PEM-encoded public key file"`
}

type decryptFlags struct {
	SymKey string `name:"symKey" aliases:"sym" help:"Password or base64-encoded key to use for symmetric AES decryption; use \"ask\" as the value to provide a password via an interactive prompt"`
	PemKey string `name:"pemKey" aliases:"pem" placeholder:"FILE" type:"existingfile" help:"Path to PEM-encoded private key file"`
}

type boolPutFlags struct {
	PublicRead bool `name:"publicRead" help:"Set the \"public-read\" ACL on the uploaded file (\"private\" ACL is set by default)"`
	SkipHash   bool `name:"nocheck" help:"Do not create backup checksums"`
	HexEncode  bool `name:"hex" help:"Create hex-encoded (rather than base64-encoded) backup checksums; unless nocheck is set"`
}

type boolGetFlags struct {
	SkipHash  bool `name:"nocheck" help:"Do not verify backup checksums"`
	HexEncode bool `name:"hex" help:"Expect hex-encoded (rather than base64-encoded) backup checksums; unless nocheck is set"`
}

type awsFlags struct {
	AccessKey string   `name:"accessKey" help:"AWS Access Key ID (if not using default AWS credentials)"`
	SecretKey string   `name:"secretKey" help:"AWS Secret Key (required when accessKey is provided)"`
	Token     string   `name:"token" help:"AWS Token (effective only when accessKey is provided & only if required by your AWS setup)"`
	Region    string   `name:"region" help:"AWS Region (we use AWS defaults if not provided)"`
	Endpoint  *url.URL `name:"endpoint" placeholder:"URL" help:"Custom AWS Endpoint URL (optional)"`
}

type vaultFlags struct {
	Path     string   `name:"path" required:"" help:"Vault secret path containing backup credentials (required)"`
	IsKV2    bool     `name:"kv2" help:"Vault secret path represents a key/value version 2 secrets engine"`
	Mount    string   `name:"mount" help:"Vault approle mount path (default: approle)"`
	RoleID   string   `name:"role" env:"VAULT_ROLE_ID" help:"Vault role_id to retrieve backup credentials (either role & secret, or token)"`
	SecretID string   `name:"secret" env:"VAULT_SECRET_ID" help:"Vault secret_id to retrieve backup credentials (either role & secret, or token)"`
	Token    string   `name:"token" env:"VAULT_TOKEN" help:"Vault token to retrieve backup credentials (either role & secret, or token)"`
	CaCert   string   `name:"caCert" placeholder:"FILE" type:"existingfile" help:"Vault root certificate file (optional, or use one of VAULT_CACERT, VAULT_CACERT_BYTES, VAULT_CAPATH env vars)"`
	VaultURL *url.URL `name:"vault" placeholder:"URL" help:"Vault service url (or use VAULT_ADDR env var)"`
}

type putCmd struct {
	putArgs
	configFlags
	encryptFlags
	awsFlags
	boolPutFlags
}

type getCmd struct {
	getArgs
	configFlags
	decryptFlags
	awsFlags
	boolGetFlags
}

type vaultPutCmd struct {
	putArgs
	configFlags
	vaultFlags
	boolPutFlags
}

type vaultGetCmd struct {
	getArgs
	configFlags
	vaultFlags
	boolGetFlags
}

type genAesCmd struct{}

type genRsaCmd struct {
	PrivKey string `name:"priv" default:"private.pem" type:"path" help:"Private key file for RSA key pair"`
	PubKey  string `name:"pub" default:"public.pem" type:"path" help:"Public key file for RSA key pair"`
}

type genPassCmd struct {
	Words uint8 `short:"w" default:"10" help:"Number of words in password"`
}

type keyGenCmd struct {
	Pass genPassCmd `cmd:"" help:"Generate and print a password"`
	Aes  genAesCmd  `cmd:"" help:"Generate and print an AES key"`
	Rsa  genRsaCmd  `cmd:"" help:"Generate RSA key pair files"`
}

type encryptCmd struct {
	InFile  string `arg:"" type:"existingfile" help:"File to encrypt"`
	OutFile string `arg:"" type:"path" help:"Encrypted file"`
	encryptFlags
}

type decryptCmd struct {
	InFile  string `arg:"" type:"existingfile" help:"File to decrypt"`
	OutFile string `arg:"" type:"path" help:"Decrypted file"`
	decryptFlags
}

type verifyCmd struct {
	FilePath string `arg:"" type:"existingfile"`
	Checksum string `arg:""`
	Hex      bool   `help:"Expect a hex-encoded (rather than base64-encoded) backup checksum"`
}

type versionCmd struct{}

type appCfg struct {
	Put         putCmd           `cmd:"" help:"Upload file to S3 bucket using local credentials"`
	Get         getCmd           `cmd:"" help:"Download file from S3 bucket using local credentials"`
	VaultPut    vaultPutCmd      `cmd:"" help:"Upload file to S3 bucket using credentials from vault"`
	VaultGet    vaultGetCmd      `cmd:"" help:"Download file from S3 bucket using credentials from vault"`
	Keygen      keyGenCmd        `cmd:"" help:"Generate backup keys (Password, AES, RSA)"`
	Encrypt     encryptCmd       `cmd:"" help:"Encrypt a local file"`
	Decrypt     decryptCmd       `cmd:"" help:"Decrypt a local file"`
	Verify      verifyCmd        `cmd:"" help:"Verify a checksum against a local file"`
	Version     versionCmd       `cmd:"" help:"Print version and exit"`
	VersionFlag kong.VersionFlag `short:"v" name:"version" help:"Print version and exit"`
}

func main() {
	app := kong.Parse(&appCfg{},
		kong.HelpOptions{Compact: true},
		kong.Description("S3 backup script in a single binary"),
		kong.Configuration(kongyaml.Loader),
		kong.Vars{"version": version()},
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	app.BindTo(ctx, (*context.Context)(nil))
	if err := app.Run(); err != nil {
		log.Fatalln(err)
	}
}

// ============================================================
// CLI commands
// ============================================================

func (versionCmd) Run() error {
	fmt.Println(version())
	return nil
}

func (c *putCmd) Run(ctx context.Context) error {
	remote, local, err := checkPaths(c.RemotePath, c.LocalPath)
	if err != nil {
		return err
	}
	co := cipherOpts{
		symKeyValue: c.SymKey,
		pemKeyFile:  c.PemKey,
	}
	ho := hashOpts{
		skipHash:  c.SkipHash,
		hexEncode: c.HexEncode,
	}
	cl, err := c.Client(co, ho)
	if err != nil {
		return err
	}
	return cl.PutLocalFile(ctx, remote, local, c.PublicRead)
}

func (c *getCmd) Run(ctx context.Context) error {
	remote, local, err := checkPaths(c.RemotePath, c.LocalPath)
	if err != nil {
		return err
	}
	co := cipherOpts{
		symKeyValue: c.SymKey,
		pemKeyFile:  c.PemKey,
	}
	ho := hashOpts{
		skipHash:  c.SkipHash,
		hexEncode: c.HexEncode,
	}
	cl, err := c.Client(co, ho)
	if err != nil {
		return err
	}
	return cl.GetRemoteFile(ctx, remote, local)
}

func (c *vaultPutCmd) Run(ctx context.Context) error {
	cfg, err := c.Config(ctx)
	if err != nil {
		return err
	}

	var endpoint *url.URL
	if cfg.S3Endpoint != "" {
		endpoint, err = url.Parse(cfg.S3Endpoint)
		if err != nil {
			return err
		}
	}

	var pemKeyFile string
	if cfg.PublicKey != "" {
		pemKeyFile, err = createPemKeyFile("pub", cfg.PublicKey)
		if err != nil {
			return err
		}
	}
	defer removePemKeyFile(pemKeyFile)

	cmd := &putCmd{
		putArgs:      c.putArgs,
		SymKey:       cfg.CipherKey,
		PemKey:       pemKeyFile,
		AccessKey:    cfg.S3AccessKey,
		SecretKey:    cfg.S3SecretKey,
		Token:        cfg.S3Token,
		Region:       cfg.S3Region,
		Endpoint:     endpoint,
		boolPutFlags: c.boolPutFlags,
	}
	return cmd.Run(ctx)
}

func (c *vaultGetCmd) Run(ctx context.Context) error {
	cfg, err := c.Config(ctx)
	if err != nil {
		return err
	}

	var endpoint *url.URL
	if cfg.S3Endpoint != "" {
		endpoint, err = url.Parse(cfg.S3Endpoint)
		if err != nil {
			return err
		}
	}

	var pemKeyFile string
	if cfg.PrivateKey != "" {
		pemKeyFile, err = createPemKeyFile("priv", cfg.PrivateKey)
		if err != nil {
			return err
		}
	}
	defer removePemKeyFile(pemKeyFile)

	cmd := &getCmd{
		getArgs:      c.getArgs,
		SymKey:       cfg.CipherKey,
		PemKey:       pemKeyFile,
		AccessKey:    cfg.S3AccessKey,
		SecretKey:    cfg.S3SecretKey,
		Token:        cfg.S3Token,
		Region:       cfg.S3Region,
		Endpoint:     endpoint,
		boolGetFlags: c.boolGetFlags,
	}
	return cmd.Run(ctx)
}

func (*genAesCmd) Run() error {
	fmt.Println(crypto.GenerateAESKeyString())
	return nil
}

func (c *genRsaCmd) Run() error {
	return crypto.GenerateRSAKeyPair(c.PrivKey, c.PubKey)
}

func (c *genPassCmd) Run() error {
	words := make([]string, c.Words)
	for i := range words {
		word, err := crypto.RandomWord()
		if err != nil {
			return err
		}
		words[i] = word
	}
	fmt.Println(strings.Join(words, "-"))
	return nil
}

func (c *encryptCmd) Run() error {
	opts := cipherOpts{
		symKeyValue: c.SymKey,
		pemKeyFile:  c.PemKey,
	}
	cipher, err := opts.MustCipher()
	if err != nil {
		return err
	}
	return cipher.Encrypt(c.InFile, c.OutFile)
}

func (c *decryptCmd) Run() error {
	opts := cipherOpts{
		symKeyValue: c.SymKey,
		pemKeyFile:  c.PemKey,
	}
	cipher, err := opts.MustCipher()
	if err != nil {
		return err
	}
	return cipher.Decrypt(c.InFile, c.OutFile)
}

func (c *verifyCmd) Run() error {
	h := crypto.NewHash(c.Hex)
	return h.Verify(c.FilePath, c.Checksum)
}

// ============================================================
// Common actions
// ============================================================

func version() string {
	if tag != "" && commit != "" {
		return fmt.Sprintf("%s (%s)", tag, commit)
	}
	if info, ok := debug.ReadBuildInfo(); ok {
		if rev := info.Main.Version; rev != "" {
			return rev
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

func (f awsFlags) Client(co cipherOpts, ho hashOpts) (*client.Client, error) {
	aws := store.AwsS3{
		AccessKey: f.AccessKey,
		SecretKey: f.SecretKey,
		Token:     f.Token,
		Region:    f.Region,
	}
	if f.Endpoint != nil {
		aws.Endpoint = f.Endpoint.String()
	}
	backend, err := aws.Store()
	if err != nil {
		return nil, err
	}
	cipher, err := co.MaybeCipher()
	if err != nil {
		return nil, err
	}
	return &client.Client{
		Hash:   ho.Hash(),
		Cipher: cipher,
		Store:  backend,
	}, nil
}

type hashOpts struct {
	skipHash  bool
	hexEncode bool
}

func (o hashOpts) Hash() client.Hash {
	if !o.skipHash {
		return crypto.NewHash(o.hexEncode)
	}
	return nil
}

type cipherOpts struct {
	symKeyValue string
	pemKeyFile  string
}

func (o cipherOpts) MaybeCipher() (client.Cipher, error) {
	symKey := o.symKeyValue
	if symKey == "ask" {
		fmt.Print("Enter password or base64-encoded key: ")
		// hush goland, it's not redundant on Windows
		//goland:noinspection GoRedundantConversion
		password, err := term.ReadPassword(int(syscall.Stdin))
		if err != nil {
			return nil, err
		}
		symKey = strings.TrimSpace(string(password))
		if symKey == "" {
			return nil, errors.New("empty passwords are not allowed")
		}
	}
	if symKey != "" {
		return crypto.NewAESCipher(symKey)
	}
	if o.pemKeyFile != "" {
		return crypto.NewRSACipher(o.pemKeyFile)
	}
	return nil, nil
}

func (o cipherOpts) MustCipher() (client.Cipher, error) {
	cipher, err := o.MaybeCipher()
	if err != nil || cipher != nil {
		return cipher, err
	}
	return nil, errors.New("either one of symKey or pemKey is required")
}

func (f vaultFlags) Config(ctx context.Context) (*config.Config, error) {
	vault := config.Vault{
		Path:       f.Path,
		IsKV2:      f.IsKV2,
		Mount:      f.Mount,
		Token:      f.Token,
		RoleID:     f.RoleID,
		SecretID:   f.SecretID,
		CaCertFile: f.CaCert,
	}
	if f.VaultURL != nil {
		vault.VaultAddr = f.VaultURL.String()
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
