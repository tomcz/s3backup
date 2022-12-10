package store

import (
	"fmt"
	"os"
	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"

	"github.com/tomcz/s3backup/client"
)

const checksumKey = "S3-Backup-Checksum"

var s3PathPattern = regexp.MustCompile(`^s3://([^/]+)/(.+)$`)

type s3store struct {
	api *s3.S3
}

func NewS3(awsAccessKey, awsSecretKey, awsToken, awsRegion, awsEndpoint string) (client.Store, error) {
	var cfg []*aws.Config
	if awsAccessKey != "" && awsSecretKey != "" {
		cfg = append(cfg, &aws.Config{
			Credentials: credentials.NewStaticCredentials(
				awsAccessKey,
				awsSecretKey,
				awsToken,
			),
		})
	}
	if awsRegion != "" {
		cfg = append(cfg, &aws.Config{
			Region: aws.String(awsRegion),
		})
	}
	if awsEndpoint != "" {
		cfg = append(cfg, &aws.Config{
			Endpoint:         aws.String(awsEndpoint),
			S3ForcePathStyle: aws.Bool(true), // gofakes3 and DigitalOcean's Spaces need this
		})
	}
	awsSession, err := session.NewSession(cfg...)
	if err != nil {
		return nil, err
	}
	return &s3store{s3.New(awsSession)}, nil
}

func (s *s3store) IsRemote(path string) bool {
	return s3PathPattern.MatchString(path)
}

func (s *s3store) UploadFile(remotePath, localPath, checksum string) error {
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
	_, err = uploader.Upload(input)
	if err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}
	return nil
}

func (s *s3store) DownloadFile(remotePath, localPath string, readChecksum bool) (string, error) {
	bucket, objectKey, err := splitRemotePath(remotePath)
	if err != nil {
		return "", err
	}

	var checksum string
	if readChecksum {
		res, cerr := s.api.HeadObject(&s3.HeadObjectInput{
			Bucket: aws.String(bucket),
			Key:    aws.String(objectKey),
		})
		if cerr != nil {
			return "", fmt.Errorf("failed to read checksum: %w", cerr)
		}
		hash, ok := res.Metadata[checksumKey]
		if ok {
			checksum = *hash
		}
	}

	file, err := os.Create(localPath)
	if err != nil {
		return "", fmt.Errorf("cannot create %q: %w", localPath, err)
	}
	defer file.Close()

	downloader := s3manager.NewDownloaderWithClient(s.api)
	_, err = downloader.Download(file, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return "", fmt.Errorf("download failed: %w", err)
	}
	return checksum, nil
}

func splitRemotePath(remotePath string) (bucket string, objectKey string, err error) {
	if md := s3PathPattern.FindStringSubmatch(remotePath); md != nil {
		bucket = md[1]
		objectKey = md[2]
	} else {
		err = fmt.Errorf("%q is not a valid S3 path", remotePath)
	}
	return // bucket, objectKey, err
}
