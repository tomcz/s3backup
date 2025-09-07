package store

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/request"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"

	"github.com/tomcz/s3backup/v2/internal/client"
)

const checksumKey = "S3-Backup-Checksum"

type AwsOpts struct {
	AccessKey string
	SecretKey string
	Token     string
	Region    string
	Endpoint  string
}

type s3store struct {
	api *s3.S3
}

func NewS3(opts AwsOpts) (client.Store, error) {
	var cfg []*aws.Config
	if opts.AccessKey != "" && opts.SecretKey != "" {
		cfg = append(cfg, &aws.Config{
			Credentials: credentials.NewStaticCredentials(
				opts.AccessKey,
				opts.SecretKey,
				opts.Token,
			),
		})
	}
	if opts.Region != "" {
		cfg = append(cfg, &aws.Config{
			Region: aws.String(opts.Region),
		})
	}
	if opts.Endpoint != "" {
		cfg = append(cfg, &aws.Config{
			Endpoint:         aws.String(opts.Endpoint),
			S3ForcePathStyle: aws.Bool(true), // gofakes3 and DigitalOcean's Spaces need this
		})
	}
	awsSession, err := session.NewSession(cfg...)
	if err != nil {
		return nil, err
	}
	return &s3store{s3.New(awsSession)}, nil
}

func (s *s3store) UploadFile(ctx context.Context, remotePath, localPath, checksum string) error {
	bucket, objectKey, err := splitRemotePath(remotePath)
	if err != nil {
		return err
	}

	file, err := os.Open(localPath)
	if err != nil {
		return fmt.Errorf("cannot open %q: %w", localPath, err)
	}
	defer file.Close()

	uploader := s3manager.NewUploaderWithClient(s.api)
	input := &s3manager.UploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
		Body:   file,
	}
	if checksum != "" {
		input.Metadata = map[string]*string{
			checksumKey: aws.String(checksum),
		}
	}
	_, err = uploader.UploadWithContext(ctx, input)
	if err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}
	return nil
}

func (s *s3store) DownloadFile(ctx context.Context, remotePath, localPath string) (string, error) {
	bucket, objectKey, err := splitRemotePath(remotePath)
	if err != nil {
		return "", err
	}

	file, err := os.Create(localPath)
	if err != nil {
		return "", fmt.Errorf("cannot create %q: %w", localPath, err)
	}
	defer file.Close()

	var checksum string
	downloader := s3manager.NewDownloaderWithClient(s.api)
	req := &s3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(objectKey)}
	opt := request.WithGetResponseHeader(fmt.Sprintf("x-amz-meta-%s", checksumKey), &checksum)
	_, err = downloader.DownloadWithContext(ctx, file, req, s3manager.WithDownloaderRequestOptions(opt))
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	return checksum, nil
}
