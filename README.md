# S3 backup script in a single binary

Provides a standard way of backing up an archive to a S3 bucket, and restoring the backed up
archive from its S3 bucket. No more custom backup scripts please ...

## Upload process:

1. Encrypt file to be backed up (optional but highly recommended). `s3backup` encrypts using
AES-CTR and can use either a 256-bit Base64-encoded symmetric key, or a PEM-encoded RSA public
key for encryption. If a public key is provided, `s3backup` will generate a random 256-bit
symmetric key which will be encrypted using the public key and stored with the encrypted file.

2. Calculate a SHA-256 checksum for the file to be uploaded. For encrypted uploads the checksum
is calculated on the encrypted file.

3. Upload to AWS S3 using concurrent uploads to handle large files and store the checksum with
the uploaded file.

## Download process:

1. Download file from AWS S3 using concurrent downloads to handle large files and retrieve the
stored checksum of the uploaded file.

2. Verify that the stored checksum matches the downloaded file.

3. Optionally, decrypt the downloaded file using either the same symmetric key that was used
to encrypt it, or the RSA private key matching the RSA public key that was used for encryption.

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
Usage: ./bin/s3backup [options] s3://bucket/objectkey local_file_path
  -v    Show version and exit
  -get  Get remote file from s3 bucket (send by default)
  -symKey string
        Base64-encoded 256-bit symmetric key
        (for optional, but recommended, client-side encryption & decryption)
  -pemKey string
        Path to PEM-encoded public or private key file
        (for optional, but recommended, client-side encryption & decryption)
  -accessKey string
        AWS Access Key ID (if not using default AWS credentials)
  -secretKey string
        AWS Secret Key (required if accessKey provided)
  -token string
        AWS Token (possibly required if accessKey provided)
  -region string
        AWS Region (required if accessKey provided)
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
