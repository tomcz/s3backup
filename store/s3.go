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
)

const checksumKey = "S3-Backup-Checksum"

var s3PathPattern = regexp.MustCompile(`^s3://([^/]+)/(.+)$`)

type s3store struct {
	client *s3.S3
}

func NewS3(awsAccessKey, awsSecretKey, awsToken, awsRegion, awsEndpoint string) (Store, error) {
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

func (s *s3store) UploadFile(remotePath, localPath, checksum string) error {
	bucket, objectKey, err := splitRemotePath(remotePath)
	if err != nil {
		return err
	}

	file, err := os.Open(localPath)
	if err != nil {
		return err
	}
	defer file.Close()

	uploader := s3manager.NewUploaderWithClient(s.client)
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
	return err
}

func (s *s3store) DownloadFile(remotePath, localPath string) (checksum string, err error) {
	bucket, objectKey, err := splitRemotePath(remotePath)
	if err != nil {
		return
	}

	res, err := s.client.HeadObject(&s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return
	}
	hash, ok := res.Metadata[checksumKey]
	if ok {
		checksum = *hash
	}

	file, err := os.Create(localPath)
	if err != nil {
		return
	}
	defer file.Close()

	downloader := s3manager.NewDownloaderWithClient(s.client)
	_, err = downloader.Download(file, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
	})
	return // checksum, err
}

func splitRemotePath(remotePath string) (bucket string, objectKey string, err error) {
	if md := s3PathPattern.FindStringSubmatch(remotePath); md != nil {
		bucket = md[1]
		objectKey = md[2]
	} else {
		err = fmt.Errorf("%v is not a valid S3 path", remotePath)
	}
	return // bucket, objectKey, err
}
