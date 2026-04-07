package store

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager"
	"github.com/aws/aws-sdk-go-v2/feature/s3/transfermanager/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"

	"github.com/tomcz/s3backup/v2/internal/client"
)

const checksumKey = "S3-Backup-Checksum"

type AwsS3 struct {
	AccessKey string
	SecretKey string
	Token     string
	Region    string
	Endpoint  string
}

type s3store struct {
	client   *s3.Client // for tests
	transfer *transfermanager.Client
}

func (a AwsS3) Store() (client.Store, error) {
	var opts []func(*config.LoadOptions) error
	if a.AccessKey != "" && a.SecretKey != "" {
		provider := credentials.NewStaticCredentialsProvider(a.AccessKey, a.SecretKey, a.Token)
		opts = append(opts, config.WithCredentialsProvider(provider))
	}
	if a.Region != "" {
		opts = append(opts, config.WithRegion(a.Region))
	}
	if a.Endpoint != "" {
		opts = append(opts, config.WithBaseEndpoint(a.Endpoint))
	}
	sdkConfig, err := config.LoadDefaultConfig(context.Background(), opts...)
	if err != nil {
		return nil, err
	}
	s3Client := s3.NewFromConfig(sdkConfig)
	return &s3store{
		client:   s3Client,
		transfer: transfermanager.New(s3Client),
	}, nil
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

	req := &transfermanager.UploadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
		Body:   file,
		ACL:    types.ObjectCannedACLPrivate,
	}
	if checksum != "" {
		req.Metadata = map[string]string{
			checksumKey: checksum,
		}
	}
	_, err = s.transfer.UploadObject(ctx, req)
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

	req := &transfermanager.DownloadObjectInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(objectKey),
		WriterAt: file,
	}
	res, err := s.transfer.DownloadObject(ctx, req)
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	// metadata keys are all normalized to lower-case
	return res.Metadata[strings.ToLower(checksumKey)], nil
}
