# S3 backup script in a single binary

Provides a standard way of backing up an archive to a S3 bucket, and restoring the backed up
archive from its S3 bucket. No more custom backup scripts please ...

## Upload process

1. Encrypt file to be backed up (optional but highly recommended). `s3backup` encrypts using
AES-CTR and can use either a 256-bit Base64-encoded symmetric key, or a PEM-encoded RSA public
key for encryption. If a public key is provided, `s3backup` will generate a random 256-bit
symmetric key which will be encrypted using the public key and stored with the encrypted file.

2. Calculate a SHA-256 checksum for the file to be uploaded. For encrypted uploads the checksum
is calculated on the encrypted file.

3. Upload to AWS S3 using concurrent uploads to handle large files and store the checksum with
the uploaded file.

## Download process

1. Download file from AWS S3 using concurrent downloads to handle large files and retrieve the
stored checksum of the uploaded file.

2. Verify that the stored checksum matches the downloaded file.

3. Optionally, decrypt the downloaded file using either the same symmetric key that was used
to encrypt it, or the RSA private key matching the RSA public key that was used for encryption.

## HashiCorp Vault

`s3backup` provides `vault-get` and `vault-put` commands that allow it to be configured using
secrets held by a [vault](https://www.vaultproject.io/) instance so that you can store encryption
keys and AWS credentials in a secure manner.

Vault integration in `s3backup` can be configured from the command line and using vault's own
[environment variables](https://www.vaultproject.io/docs/commands/environment.html).

## Installation

Clone this repository

```
git clone git@github.com:tomcz/s3backup.git
```

Install `s3backup` and `s3keygen` into `$GOPATH/bin`

```
make install
```

## Usage

```
Usage:
  s3backup [command]

Available Commands:
  get         Get local file from S3 bucket using local credentials
  help        Help about any command
  put         Put local file to S3 bucket using local credentials
  vault-get   Get local file from S3 bucket using credentials from vault
  vault-put   Put local file to S3 bucket using credentials from vault
  version     Print version and exit

Flags:
  -h, --help   help for s3backup

Use "s3backup [command] --help" for more information about a command.
```

[Click here](https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html)
for details about using default AWS credentials.

## Backup key generation

To make things easier, this project also provides `s3keygen` to create 256-bit symmetric keys
and 2048-bit RSA private/public key pairs for use by `s3backup`.

```
Usage of ./bin/s3keygen:
  -v    Show version and exit
  -t string
        Key type: aes or rsa (default "aes")
  -priv string
        Private key file for rsa key pair (default "private.pem")
  -pub string
        Public key file for rsa key pair (default "public.pem")
```
