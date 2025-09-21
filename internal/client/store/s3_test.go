package store

import (
	"crypto/rand"
	"net/http/httptest"
	"os"
	"path"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"gotest.tools/v3/assert"
)

func TestRoundTripUploadDownload_withChecksum(t *testing.T) {
	backend := s3mem.New()
	faker := gofakes3.New(backend)
	ts := httptest.NewServer(faker.Server())
	defer ts.Close()

	expected := make([]byte, 4096)
	_, _ = rand.Read(expected)

	uploadFile := path.Join(t.TempDir(), "upload")
	err := os.WriteFile(uploadFile, expected, 0600)
	assert.NilError(t, err, "Cannot create file to upload")

	accessKey := "AKIAIOSFODNN7EXAMPLE"
	secretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	cfg := AwsS3{
		AccessKey: accessKey,
		SecretKey: secretKey,
		Region:    "us-east-1",
		Endpoint:  ts.URL,
	}
	store, err := cfg.Store()
	assert.NilError(t, err, "failed to create S3 client")

	impl := store.(*s3store)
	_, err = impl.api.CreateBucket(&s3.CreateBucketInput{Bucket: aws.String("test-bucket")})
	assert.NilError(t, err, "failed to create bucket")

	err = store.UploadFile(t.Context(), "s3://test-bucket/test-file", uploadFile, "wibble")
	assert.NilError(t, err, "failed to upload file")

	downloadFile := uploadFile + ".download"
	checksum, err := store.DownloadFile(t.Context(), "s3://test-bucket/test-file", downloadFile)
	assert.NilError(t, err, "failed to download file")

	actual, err := os.ReadFile(downloadFile)
	assert.NilError(t, err, "Cannot read downloaded file")

	assert.Equal(t, "wibble", checksum)
	assert.DeepEqual(t, expected, actual)
}

func TestRoundTripUploadDownload_withoutChecksum(t *testing.T) {
	backend := s3mem.New()
	faker := gofakes3.New(backend)
	ts := httptest.NewServer(faker.Server())
	defer ts.Close()

	expected := make([]byte, 4096)
	_, _ = rand.Read(expected)

	uploadFile := path.Join(t.TempDir(), "upload")
	err := os.WriteFile(uploadFile, expected, 0600)
	assert.NilError(t, err, "Cannot create file to upload")

	accessKey := "AKIAIOSFODNN7EXAMPLE"
	secretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	cfg := AwsS3{
		AccessKey: accessKey,
		SecretKey: secretKey,
		Region:    "us-east-1",
		Endpoint:  ts.URL,
	}
	store, err := cfg.Store()
	assert.NilError(t, err, "failed to create S3 client")

	impl := store.(*s3store)
	_, err = impl.api.CreateBucket(&s3.CreateBucketInput{Bucket: aws.String("test-bucket")})
	assert.NilError(t, err, "failed to create bucket")

	err = store.UploadFile(t.Context(), "s3://test-bucket/test-file", uploadFile, "")
	assert.NilError(t, err, "failed to upload file")

	downloadFile := uploadFile + ".download"
	checksum, err := store.DownloadFile(t.Context(), "s3://test-bucket/test-file", downloadFile)
	assert.NilError(t, err, "failed to download file")

	actual, err := os.ReadFile(downloadFile)
	assert.NilError(t, err, "Cannot read downloaded file")

	assert.Equal(t, "", checksum)
	assert.DeepEqual(t, expected, actual)
}
