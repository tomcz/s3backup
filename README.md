# S3 backup script in a single binary

Provides a standard way of backing up an archive to a S3 bucket, and restoring the backed up archive from its S3 bucket. No more custom backup scripts please ...

You can download the latest release from [here](https://github.com/tomcz/s3backup/releases).

## Upload process

1. Encrypt the file to be backed up (optional but highly recommended). `s3backup` uses AES-256 encryption via a password of your choice (with optional scrypt key derivation), a Base64-encoded secret key, or a PEM-encoded RSA public key. If a public key is provided, `s3backup` will generate a random 256-bit symmetric key which will be encrypted using the public key and stored with the encrypted file. To make key creation easier, you can use the `keygen` commands as outlined [below](#backup-key-generation).

2. Calculate SHA-256 checksum for the file to be uploaded. For encrypted uploads the checksum is calculated on the encrypted file.

3. Upload to AWS S3 using concurrent uploads to handle large files and store the checksum with the uploaded file.

## Download process

1. Download file from AWS S3 using concurrent downloads to handle large files and retrieve the stored checksum of the uploaded file.

2. Verify that the stored checksum matches the downloaded file.

3. Optionally decrypt the downloaded file using either the same password or symmetric key that was used to encrypt it, or the RSA private key matching the RSA public key that was used for encryption.

## Usage

```
Usage: s3backup <command>

S3 backup script in a single binary.

NOTE: Command flag values can optionally be retrieved from a JSON configuration
file. The path to this configuration file is provided at runtime by the
S3BACKUP_JSON environment variable. This JSON file should contain an object
whose keys must match the command flags they are meant to configure.

Flags:
  -h, --help    Show context-sensitive help.

Commands:
  put           Upload file to S3 bucket using local AWS credentials
  get           Download file from S3 bucket using local AWS credentials
  vault-put     Upload file to S3 bucket using AWS credentials from Vault
  vault-get     Download file from S3 bucket using AWS credentials from Vault
  keygen aes    Generate and print AES key
  keygen rsa    Generate RSA key pair files
  encrypt       Encrypt a local file
  decrypt       Decrypt a local file
  version       Print version and exit

Run "s3backup <command> --help" for more information on a command.
```

### AWS S3 Credentials

AWS S3 integration in `s3backup` can be configured from the command line, and/or an optional JSON configuration file, and using AWS environment variables and config files. [Click here](https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html) for details on using default AWS credentials.

#### s3backup put

```
Usage: s3backup put <local-path> <remote-path> [flags]

Upload file to S3 bucket using local AWS credentials

Arguments:
  <local-path>     Required local file path
  <remote-path>    Required s3 path (s3://bucket/objectkey)

Flags:
  -h, --help               Show context-sensitive help.

      --nocheck            Do not create backup checksums
      --symKey=value       Password or base64-encoded key to use for symmetric
                           AES encryption (Use 'ask' to enter a password or key
                           via an interactive prompt)
      --derive             Use cryptographic key derivation from symKey
                           passwords. Slower, but stronger and more secure keys
      --pemKey=FILE        Path to PEM-encoded public key file
      --accessKey=value    AWS Access Key ID (if not using default AWS
                           credentials)
      --secretKey=value    AWS Secret Key (required when accessKey is provided)
      --token=value        AWS Token (effective only when accessKey is provided,
                           depends on your AWS setup)
      --region=value       AWS Region (we use AWS defaults if not provided)
      --endpoint=URL       Custom AWS Endpoint URL (optional)
```

#### s3backup get

```
Usage: s3backup get <remote-path> <local-path> [flags]

Download file from S3 bucket using local AWS credentials

Arguments:
  <remote-path>    Required s3 path (s3://bucket/objectkey)
  <local-path>     Required local file path

Flags:
  -h, --help               Show context-sensitive help.

      --nocheck            Do not verify backup checksums
      --symKey=value       Password or base64-encoded key to use for symmetric
                           AES decryption (Use 'ask' to enter a password or key
                           via an interactive prompt)
      --derive             Use cryptographic key derivation from symKey
                           passwords. Slower, but stronger and more secure keys
      --pemKey=FILE        Path to PEM-encoded private key file
      --accessKey=value    AWS Access Key ID (if not using default AWS
                           credentials)
      --secretKey=value    AWS Secret Key (required when accessKey is provided)
      --token=value        AWS Token (effective only when accessKey is provided,
                           depends on your AWS setup)
      --region=value       AWS Region (we use AWS defaults if not provided)
      --endpoint=URL       Custom AWS Endpoint URL (optional)
```

### HashiCorp Vault

`s3backup` provides `vault-put` and `vault-get` commands that allow it to be configured using secrets held by a [vault](https://www.vaultproject.io/) instance so that you can store encryption keys and AWS credentials in a secure manner. The secrets that you need to hold in vault for `s3backup` are described [here](https://github.com/tomcz/s3backup/blob/master/config/config.go).

Vault integration in `s3backup` can be configured from the command line, and/or an optional JSON configuration file, and using vault's own [environment variables](https://www.vaultproject.io/docs/commands/environment.html).

#### s3backup vault-put

```
Usage: s3backup vault-put --path=value <local-path> <remote-path> [flags]

Upload file to S3 bucket using AWS credentials from Vault

Arguments:
  <local-path>     Required local file path
  <remote-path>    Required s3 path (s3://bucket/objectkey)

Flags:
  -h, --help            Show context-sensitive help.

      --nocheck         Do not create backup checksums
      --path=value      Vault secret path containing backup credentials
                        (required)
      --kv2             Vault secret path represents a key/value version 2
                        secrets engine
      --mount=value     Vault approle mount path (default: approle)
      --role=value      Vault approle role_id to retrieve backup credentials
                        (either role & secret, or token are required)
                        ($VAULT_ROLE_ID)
      --secret=value    Vault approle secret_id to retrieve backup credentials
                        (either role & secret, or token are required)
                        ($VAULT_SECRET_ID)
      --token=value     Vault token to retrieve backup credentials (either role
                        & secret, or token are required) ($VAULT_TOKEN)
      --caCert=FILE     Vault Root CA certificate (optional, or use one of
                        VAULT_CACERT, VAULT_CACERT_BYTES, VAULT_CAPATH env vars)
      --vault=URL       Vault service URL (or use VAULT_ADDR env var)
```

#### s3backup vault-get

```
Usage: s3backup vault-get --path=value <remote-path> <local-path> [flags]

Download file from S3 bucket using AWS credentials from Vault

Arguments:
  <remote-path>    Required s3 path (s3://bucket/objectkey)
  <local-path>     Required local file path

Flags:
  -h, --help            Show context-sensitive help.

      --nocheck         Do not verify backup checksums
      --path=value      Vault secret path containing backup credentials
                        (required)
      --kv2             Vault secret path represents a key/value version 2
                        secrets engine
      --mount=value     Vault approle mount path (default: approle)
      --role=value      Vault approle role_id to retrieve backup credentials
                        (either role & secret, or token are required)
                        ($VAULT_ROLE_ID)
      --secret=value    Vault approle secret_id to retrieve backup credentials
                        (either role & secret, or token are required)
                        ($VAULT_SECRET_ID)
      --token=value     Vault token to retrieve backup credentials (either role
                        & secret, or token are required) ($VAULT_TOKEN)
      --caCert=FILE     Vault Root CA certificate (optional, or use one of
                        VAULT_CACERT, VAULT_CACERT_BYTES, VAULT_CAPATH env vars)
      --vault=URL       Vault service URL (or use VAULT_ADDR env var)
```

## Backup key generation

To make things easier, `s3backup` also provides `keygen` commands to create 256-bit symmetric keys and 4096-bit RSA private/public key pairs suitable for use by `s3backup`.

```
Usage: s3backup keygen <command>

Generate RSA or AES backup keys

Flags:
  -h, --help    Show context-sensitive help.

Commands:
  keygen aes    Generate and print AES key
  keygen rsa    Generate RSA key pair files
```

## Build

1. Install Go 1.24 from https://golang.org/
2. Build the binaries: `make build`
