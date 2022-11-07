# S3 backup script in a single binary

Provides a standard way of backing up an archive to a S3 bucket, and restoring the backed up archive from its S3 bucket. No more custom backup scripts please ...

You can download the latest release from [here](https://github.com/tomcz/s3backup/releases).

## Upload process

1. Encrypt the file to be backed up (optional but highly recommended). `s3backup` uses AES-256 encryption via a password of your choice, a Base64-encoded secret key, or a PEM-encoded RSA public key. If a public key is provided, `s3backup` will generate a random 256-bit symmetric key which will be encrypted using the public key and stored with the encrypted file. To make key creation easier, you can use the `keygen` commands as outlined [below](#backup-key-generation).

2. Calculate SHA-256 checksum for the file to be uploaded. For encrypted uploads the checksum is calculated on the encrypted file.

3. Upload to AWS S3 using concurrent uploads to handle large files and store the checksum with the uploaded file.

## Download process

1. Download file from AWS S3 using concurrent downloads to handle large files and retrieve the stored checksum of the uploaded file.

2. Verify that the stored checksum matches the downloaded file.

3. Optionally decrypt the downloaded file using either the same password or symmetric key that was used to encrypt it, or the RSA private key matching the RSA public key that was used for encryption.

## Usage

```
NAME:
   s3backup - S3 backup script in a single binary

USAGE:
   s3backup [global options] command [command options] [arguments...]

COMMANDS:
   version    Print version and exit
   put        Upload file to S3 bucket using local credentials
   get        Download file from S3 bucket using local credentials
   vault-put  Upload file to S3 bucket using credentials from vault
   vault-get  Download file from S3 bucket using credentials from vault
   keygen     Generate RSA and AES backup keys
   encrypt    Just encrypt a local file
   decrypt    Just decrypt a local file
   help, h    Shows a list of commands or help for one command

GLOBAL OPTIONS:
   --help, -h     show help (default: false)
   --version, -v  print the version (default: false)
```

### AWS S3 Credentials

AWS S3 integration in `s3backup` can be configured from the command line, and using AWS environment variables and config files. [Click here](https://docs.aws.amazon.com/sdk-for-go/v1/developer-guide/configuring-sdk.html) for details on using default AWS credentials.

#### s3backup put

```
NAME:
   s3backup put - Upload file to S3 bucket using local credentials

USAGE:
   s3backup put [command options] local_file_path s3://bucket/objectkey

OPTIONS:
   --symKey value     Password to use for symmetric AES encryption (optional)
   --pemKey FILE      Path to PEM-encoded public key FILE (optional)
   --accessKey value  AWS Access Key ID (if not using default AWS credentials)
   --secretKey value  AWS Secret Key (required when accessKey is provided)
   --token value      AWS Token (effective only when accessKey is provided, depends on your AWS setup)
   --region value     AWS Region (we use AWS defaults if not provided)
   --endpoint URL     Custom AWS Endpoint URL (optional)
   --nocheck          Do not create backup checksums (default: false)
```

#### s3backup get

```
NAME:
   s3backup get - Download file from S3 bucket using local credentials

USAGE:
   s3backup get [command options] s3://bucket/objectkey local_file_path

OPTIONS:
   --symKey value     Password to use for symmetric AES decryption (optional)
   --pemKey FILE      Path to PEM-encoded private key FILE (optional)
   --accessKey value  AWS Access Key ID (if not using default AWS credentials)
   --secretKey value  AWS Secret Key (required when accessKey is provided)
   --token value      AWS Token (effective only when accessKey is provided, depends on your AWS setup)
   --region value     AWS Region (we use AWS defaults if not provided)
   --endpoint URL     Custom AWS Endpoint URL (optional)
   --nocheck          Do not verify backup checksums (default: false)
```

### HashiCorp Vault

`s3backup` provides `vault-put` and `vault-get` commands that allow it to be configured using secrets held by a [vault](https://www.vaultproject.io/) instance so that you can store encryption keys and AWS credentials in a secure manner. The secrets that you need to hold in vault for `s3backup` are described [here](https://github.com/tomcz/s3backup/blob/master/config/config.go).

Vault integration in `s3backup` can be configured from the command line, and using vault's own [environment variables](https://www.vaultproject.io/docs/commands/environment.html).

#### s3backup vault-put

```
NAME:
   s3backup vault-put - Upload file to S3 bucket using credentials from vault

USAGE:
   s3backup vault-put [command options] local_file_path s3://bucket/objectkey

OPTIONS:
   --role value    Vault role_id to retrieve backup credentials (either role & secret, or token)
   --secret value  Vault secret_id to retrieve backup credentials (either role & secret, or token)
   --token value   Vault token to retrieve backup credentials (either role & secret, or token)
   --path value    Vault secret path containing backup credentials (required)
   --caCert FILE   Vault root certificate FILE (optional)
   --vault URL     Vault service URL (required)
   --nocheck       Do not create backup checksums (default: false)
```

#### s3backup vault-get

```
NAME:
   s3backup vault-get - Download file from S3 bucket using credentials from vault

USAGE:
   s3backup vault-get [command options] s3://bucket/objectkey local_file_path

OPTIONS:
   --role value    Vault role_id to retrieve backup credentials (either role & secret, or token)
   --secret value  Vault secret_id to retrieve backup credentials (either role & secret, or token)
   --token value   Vault token to retrieve backup credentials (either role & secret, or token)
   --path value    Vault secret path containing backup credentials (required)
   --caCert FILE   Vault root certificate FILE (optional)
   --vault URL     Vault service URL (required)
   --nocheck       Do not verify backup checksums (default: false)
```

## Backup key generation

To make things easier, `s3backup` also provides `keygen` commands to create 256-bit symmetric keys and 2048-bit RSA private/public key pairs suitable for use by `s3backup`.

```
NAME:
   s3backup keygen - Generate RSA and AES backup keys

USAGE:
   s3backup keygen command [command options] [arguments...]

COMMANDS:
   aes      Generate and print AES key
   rsa      Generate RSA key pair files
   help, h  Shows a list of commands or help for one command

OPTIONS:
   --help, -h     show help (default: false)
   --version, -v  print the version (default: false)
```

## Build

1. Install Go 1.18 from https://golang.org/
2. Build the binaries: `make build`
