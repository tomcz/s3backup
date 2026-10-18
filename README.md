# S3 backup script in a single binary

Provides a standard way of backing up an archive to a S3 bucket, and restoring the backed up archive from its S3 bucket. No more custom backup scripts please ...

You can download the latest release from [here](https://github.com/tomcz/s3backup/releases).

## Upload process

1. Encrypt the file to be backed up (optional but highly recommended). `s3backup` uses AES-256 encryption via a password of your choice (with argon2 key derivation), a Base64-encoded secret key, or a PEM-encoded RSA public key. If a public key is provided, `s3backup` will generate a random 256-bit symmetric key which will be encrypted using the public key and stored with the encrypted file. To make key creation easier, you can use the `keygen` commands as outlined [below](#backup-key-generation).

2. Calculate SHA-256 checksum for the file to be uploaded. For encrypted uploads the checksum is calculated on the encrypted file.

3. Upload to AWS S3 using concurrent uploads to handle large files and store the checksum with the uploaded file.

## Download process

1. Download file from AWS S3 using concurrent downloads to handle large files and retrieve the stored checksum of the uploaded file.

2. Verify that the stored checksum matches the downloaded file.

3. Optionally decrypt the downloaded file using either the same password or symmetric key that was used to encrypt it, or the RSA private key matching the RSA public key that was used for encryption.

## Usage

```
Usage: s3backup <command> [flags]

S3 backup script in a single binary

Flags:
  -h, --help       Show context-sensitive help.
  -v, --version    Print version and exit

Commands:
  put            Upload file to S3 bucket using local credentials
  get            Download file from S3 bucket using local credentials
  vault-put      Upload file to S3 bucket using credentials from vault
  vault-get      Download file from S3 bucket using credentials from vault
  keygen pass    Generate and print a password
  keygen aes     Generate and print an AES key
  keygen rsa     Generate RSA key pair files
  encrypt        Encrypt a local file
  decrypt        Decrypt a local file
  verify         Verify a checksum against a local file
  version        Print version and exit

Run "s3backup <command> --help" for more information on a command.
```

### AWS S3 Credentials

AWS S3 integration in `s3backup` can be configured from the command line, and/or an optional YAML configuration file provided by the `S3BACKUP_YAML` environment variable (in which its YAML key names match the option names), and using AWS environment variables and config files. [Click here](https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html) for details on using default AWS credentials.

#### s3backup put

```
Usage: s3backup put <local-path> <s3://bucket/objectkey> [flags]

Upload file to S3 bucket using local credentials

Arguments:
  <local-path>               Source file path
  <s3://bucket/objectkey>    Destination S3 path

Flags:
  -h, --help                Show context-sensitive help.
  -v, --version             Print version and exit

  -c, --config-file=FILE    Path to a YAML configuration file ($S3BACKUP_YAML)
      --symKey=STRING       Password or base64-encoded key to use for symmetric
                            AES encryption; use "ask" as the value to provide a
                            password via an interactive prompt
      --pemKey=FILE         Path to PEM-encoded public key file
      --accessKey=STRING    AWS Access Key ID (if not using default AWS
                            credentials)
      --secretKey=STRING    AWS Secret Key (required when accessKey is provided)
      --token=STRING        AWS Token (effective only when accessKey is provided
                            & only if required by your AWS setup)
      --region=STRING       AWS Region (we use AWS defaults if not provided)
      --endpoint=URL        Custom AWS Endpoint URL (optional)
      --publicRead          Set the "public-read" ACL on the uploaded file
                            ("private" ACL is set by default)
      --nocheck             Do not create backup checksums
      --hex                 Create hex-encoded (rather than base64-encoded)
                            backup checksums; unless nocheck is set
```

#### s3backup get

```
Usage: s3backup get <s3://bucket/objectkey> <local-path> [flags]

Download file from S3 bucket using local credentials

Arguments:
  <s3://bucket/objectkey>    Source S3 path
  <local-path>               Destination file path

Flags:
  -h, --help                Show context-sensitive help.
  -v, --version             Print version and exit

  -c, --config-file=FILE    Path to a YAML configuration file ($S3BACKUP_YAML)
      --symKey=STRING       Password or base64-encoded key to use for symmetric
                            AES decryption; use "ask" as the value to provide a
                            password via an interactive prompt
      --pemKey=FILE         Path to PEM-encoded private key file
      --accessKey=STRING    AWS Access Key ID (if not using default AWS
                            credentials)
      --secretKey=STRING    AWS Secret Key (required when accessKey is provided)
      --token=STRING        AWS Token (effective only when accessKey is provided
                            & only if required by your AWS setup)
      --region=STRING       AWS Region (we use AWS defaults if not provided)
      --endpoint=URL        Custom AWS Endpoint URL (optional)
      --nocheck             Do not verify backup checksums
      --hex                 Expect hex-encoded (rather than base64-encoded)
                            backup checksums; unless nocheck is set
```

### HashiCorp Vault

`s3backup` provides `vault-put` and `vault-get` commands that allow it to be configured using secrets held by a [vault](https://www.vaultproject.io/) instance so that you can store encryption keys and AWS credentials in a secure manner. The secrets that you need to hold in vault for `s3backup` are described [here](https://github.com/tomcz/s3backup/blob/master/config/config.go).

Vault integration in `s3backup` can be configured from the command line, and/or an optional YAML configuration file provided by the `S3BACKUP_YAML` environment variable (in which its yaml key names match the option names), and using vault's own [environment variables](https://www.vaultproject.io/docs/commands/environment.html).

#### s3backup vault-put

```
Usage: s3backup vault-put --path=STRING <local-path> <s3://bucket/objectkey> [flags]

Upload file to S3 bucket using credentials from vault

Arguments:
  <local-path>               Source file path
  <s3://bucket/objectkey>    Destination S3 path

Flags:
  -h, --help                Show context-sensitive help.
  -v, --version             Print version and exit

  -c, --config-file=FILE    Path to a YAML configuration file ($S3BACKUP_YAML)
      --path=STRING         Vault secret path containing backup credentials
                            (required)
      --kv2                 Vault secret path represents a key/value version 2
                            secrets engine
      --mount=STRING        Vault approle mount path (default: approle)
      --role=STRING         Vault role_id to retrieve backup credentials (either
                            role & secret, or token) ($VAULT_ROLE_ID)
      --secret=STRING       Vault secret_id to retrieve backup credentials
                            (either role & secret, or token) ($VAULT_SECRET_ID)
      --token=STRING        Vault token to retrieve backup credentials (either
                            role & secret, or token) ($VAULT_TOKEN)
      --caCert=FILE         Vault root certificate file (optional, or use one of
                            VAULT_CACERT, VAULT_CACERT_BYTES, VAULT_CAPATH env
                            vars)
      --vault=URL           Vault service url (or use VAULT_ADDR env var)
      --publicRead          Set the "public-read" ACL on the uploaded file
                            ("private" ACL is set by default)
      --nocheck             Do not create backup checksums
      --hex                 Create hex-encoded (rather than base64-encoded)
                            backup checksums; unless nocheck is set
```

#### s3backup vault-get

```
Usage: s3backup vault-get --path=STRING <s3://bucket/objectkey> <local-path> [flags]

Download file from S3 bucket using credentials from vault

Arguments:
  <s3://bucket/objectkey>    Source S3 path
  <local-path>               Destination file path

Flags:
  -h, --help                Show context-sensitive help.
  -v, --version             Print version and exit

  -c, --config-file=FILE    Path to a YAML configuration file ($S3BACKUP_YAML)
      --path=STRING         Vault secret path containing backup credentials
                            (required)
      --kv2                 Vault secret path represents a key/value version 2
                            secrets engine
      --mount=STRING        Vault approle mount path (default: approle)
      --role=STRING         Vault role_id to retrieve backup credentials (either
                            role & secret, or token) ($VAULT_ROLE_ID)
      --secret=STRING       Vault secret_id to retrieve backup credentials
                            (either role & secret, or token) ($VAULT_SECRET_ID)
      --token=STRING        Vault token to retrieve backup credentials (either
                            role & secret, or token) ($VAULT_TOKEN)
      --caCert=FILE         Vault root certificate file (optional, or use one of
                            VAULT_CACERT, VAULT_CACERT_BYTES, VAULT_CAPATH env
                            vars)
      --vault=URL           Vault service url (or use VAULT_ADDR env var)
      --nocheck             Do not verify backup checksums
      --hex                 Expect hex-encoded (rather than base64-encoded)
                            backup checksums; unless nocheck is set
```

## Backup key generation

To make things easier, `s3backup` also provides `keygen` commands to create passwords, 256-bit symmetric keys, and 4096-bit RSA private/public key pairs suitable for use by `s3backup`.

```
Usage: s3backup keygen <command> [flags]

Generate backup keys (Password, AES, RSA)

Flags:
  -h, --help       Show context-sensitive help.
  -v, --version    Print version and exit

Commands:
  keygen pass    Generate and print a password
  keygen aes     Generate and print an AES key
  keygen rsa     Generate RSA key pair files
```

## Build

1. Install Go 1.27 from https://golang.org/
2. Build the binary: `make build`
