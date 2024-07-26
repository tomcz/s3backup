package store

import (
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	assert "github.com/stretchr/testify/require"

	"github.com/tomcz/s3backup/internal/utils"
)

func TestSplitRemotePath(t *testing.T) {
	bucket, objectKey, err := splitRemotePath("s3://bucket/object.key")
	assert.NoError(t, err)
	assert.Equal(t, "bucket", bucket)
	assert.Equal(t, "object.key", objectKey)

	bucket, objectKey, err = splitRemotePath("s3://some-bucket/some/path/to/object.foo")
	assert.NoError(t, err)
	assert.Equal(t, "some-bucket", bucket)
	assert.Equal(t, "some/path/to/object.foo", objectKey)

	_, _, err = splitRemotePath("http://example.com/wibble.bar")
	assert.ErrorContains(t, err, "not a valid S3 path")
}

func TestIsRemote(t *testing.T) {
	store := &s3store{}
	assert.True(t, store.IsRemote("s3://bucket/object.key"))
	assert.False(t, store.IsRemote("wibble.txt"))
}

func TestRoundTripUploadDownload_withChecksum(t *testing.T) {
	backend := s3mem.New()
	faker := gofakes3.New(backend)
	ts := httptest.NewServer(faker.Server())
	defer ts.Close()

	expected, err := utils.Random(4096)
	assert.NoError(t, err, "Cannot create file contents")

	uploadFile, err := utils.CreateTempFile("upload", expected)
	assert.NoError(t, err, "Cannot create file to upload")
	defer os.Remove(uploadFile)

	accessKey := "AKIAIOSFODNN7EXAMPLE"
	secretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	target, err := NewS3(accessKey, secretKey, "", "us-east-1", ts.URL)
	assert.NoError(t, err, "failed to create S3 client")

	impl := target.(*s3store)
	_, err = impl.api.CreateBucket(&s3.CreateBucketInput{Bucket: aws.String("test-bucket")})
	assert.NoError(t, err, "failed to create bucket")

	err = target.UploadFile("s3://test-bucket/test-file", uploadFile, "wibble")
	assert.NoError(t, err, "failed to upload file")

	downloadFile := uploadFile + ".download"
	checksum, err := target.DownloadFile("s3://test-bucket/test-file", downloadFile)
	assert.NoError(t, err, "failed to download file")
	defer os.Remove(downloadFile)

	actual, err := os.ReadFile(downloadFile)
	assert.NoError(t, err, "Cannot read downloaded file")

	assert.Equal(t, "wibble", checksum)
	assert.Equal(t, expected, actual)
}

func TestRoundTripUploadDownload_withoutChecksum(t *testing.T) {
	backend := s3mem.New()
	faker := gofakes3.New(backend)
	ts := httptest.NewServer(faker.Server())
	defer ts.Close()

	expected, err := utils.Random(4096)
	assert.NoError(t, err, "Cannot create file contents")

	uploadFile, err := utils.CreateTempFile("upload", expected)
	assert.NoError(t, err, "Cannot create file to upload")
	defer os.Remove(uploadFile)

	accessKey := "AKIAIOSFODNN7EXAMPLE"
	secretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	target, err := NewS3(accessKey, secretKey, "", "us-east-1", ts.URL)
	assert.NoError(t, err, "failed to create S3 client")

	impl := target.(*s3store)
	_, err = impl.api.CreateBucket(&s3.CreateBucketInput{Bucket: aws.String("test-bucket")})
	assert.NoError(t, err, "failed to create bucket")

	err = target.UploadFile("s3://test-bucket/test-file", uploadFile, "")
	assert.NoError(t, err, "failed to upload file")

	downloadFile := uploadFile + ".download"
	checksum, err := target.DownloadFile("s3://test-bucket/test-file", downloadFile)
	assert.NoError(t, err, "failed to download file")
	defer os.Remove(downloadFile)

	actual, err := os.ReadFile(downloadFile)
	assert.NoError(t, err, "Cannot read downloaded file")

	assert.Equal(t, "", checksum)
	assert.Equal(t, expected, actual)
}
