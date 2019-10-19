[![Build Status](https://travis-ci.org/tomcz/s3backup.svg?branch=master)](https://travis-ci.org/tomcz/s3backup)

# S3 backup script in a single binary

Provides a standard way of backing up an archive to a S3 bucket, and restoring the backed up
archive from its S3 bucket. No more custom backup scripts please ...

You can download the latest release from [here](https://github.com/tomcz/s3backup/releases).

## Upload process

1. Encrypt file to be backed up (optional but highly recommended). `s3backup` uses AES encryption,
and can use either a 256-bit Base64-encoded symmetric key, or a PEM-encoded RSA public key. If a
public key is provided, `s3backup` will generate a random 256-bit symmetric key which will be
encrypted using the public key and stored with the encrypted file. To make key creation easier,
you can use the `s3keygen` tool, as outlined [below](#backup-key-generation).

2. Calculate a SHA-256 checksum for the file to be uploaded. For encrypted uploads the checksum
is calculated on the encrypted file.

3. Upload to AWS S3 using concurrent uploads to handle large files and store the checksum with
the uploaded file.

## Download process

1. Download file from AWS S3 using concurrent downloads to handle large files and retrieve the
stored checksum of the uploaded file.

2. Verify that the stored checksum matches the downloaded file.

3. Optionally decrypt the downloaded file using either the same symmetric key that was used
to encrypt it, or the RSA private key matching the RSA public key that was used for encryption.

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

### AWS S3 Credentials

AWS S3 integration in `s3backup` can be configured from the command line, and using AWS' environment
variables and config files. [Click here](https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html)
for details on using default AWS credentials.

### HashiCorp Vault

`s3backup` provides `vault-get` and `vault-put` commands that allow it to be configured using secrets
held by a [vault](https://www.vaultproject.io/) instance so that you can store encryption keys and AWS
credentials in a secure manner. The secrets that you need to hold in vault for `s3backup` are described
[here](https://github.com/tomcz/s3backup/blob/master/config/config.go).

Vault integration in `s3backup` can be configured from the command line, and using vault's own
[environment variables](https://www.vaultproject.io/docs/commands/environment.html).

## Backup key generation

To make things easier, this project also provides `s3keygen` to create 256-bit symmetric keys
and 2048-bit RSA private/public key pairs for use by `s3backup`.

```
Usage:
  s3keygen [command]

Available Commands:
  aes         Print generated AES key
  help        Help about any command
  rsa         Generate RSA key pair
  version     Print version

Flags:
  -h, --help   help for s3keygen

Use "s3keygen [command] --help" for more information about a command.
```

## Build

1. Install Go 1.13 from https://golang.org/
2. Build the binaries: `make build`
