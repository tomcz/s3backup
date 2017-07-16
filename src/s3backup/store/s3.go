package store

import (
	"fmt"
	"log"
	"os"
	"regexp"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
)

const checksumKey = "S3-Backup-Checksum"

type Store interface {
	UploadFile(remotePath, localPath, checksum string) error
	DownloadFile(remotePath, localPath string) (string, error)
}

type s3store struct {
	client *s3.S3
}

func NewS3Store(awsAccessKey, awsSecretKey, awsToken, awsRegion string) (Store, error) {
	var sess *session.Session
	var err error

	if awsAccessKey == "" {
		log.Println("Using AWS credentials from default credential chain")
		sess, err = session.NewSession()
	} else {
		log.Println("Using AWS credentials from command line arguments")
		sess, err = session.NewSession(&aws.Config{
			Credentials: credentials.NewStaticCredentials(
				awsAccessKey,
				awsSecretKey,
				awsToken,
			),
			Region: aws.String(awsRegion),
		})
	}
	if err != nil {
		return nil, err
	}
	return &s3store{s3.New(sess)}, nil
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
	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
		Body:   file,
		Metadata: map[string]*string{
			checksumKey: aws.String(checksum),
		},
	})
	return err
}

func (s *s3store) DownloadFile(remotePath, localPath string) (string, error) {
	bucket, objectKey, err := splitRemotePath(remotePath)
	if err != nil {
		return "", err
	}

	res, err := s.client.HeadObject(&s3.HeadObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
	})
	if err != nil {
		return "", err
	}

	checksum, ok := res.Metadata[checksumKey]
	if !ok {
		return "", fmt.Errorf("%v metadata does not contain %v", remotePath, checksumKey)
	}

	file, err := os.Create(localPath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	downloader := s3manager.NewDownloaderWithClient(s.client)
	_, err = downloader.Download(file, &s3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(objectKey),
	})

	return *checksum, err
}

func splitRemotePath(remotePath string) (bucket string, objectKey string, err error) {
	s3PathPattern := regexp.MustCompile(`^s3://([^/]+)/(.+)$`)
	if md := s3PathPattern.FindStringSubmatch(remotePath); md != nil {
		bucket = md[1]
		objectKey = md[2]
	} else {
		err = fmt.Errorf("%v is not a valid S3 path", remotePath)
	}
	return // bucket, objectKey, err
}
