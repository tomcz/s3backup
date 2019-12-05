// +build integration

package store

import (
	"io/ioutil"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/s3"
	"github.com/johannesboyne/gofakes3"
	"github.com/johannesboyne/gofakes3/backend/s3mem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tomcz/s3backup/utils"
)

func TestSplitRemotePath(t *testing.T) {
	bucket, objectKey, err := splitRemotePath("s3://bucket/object.key")
	if assert.NoError(t, err) {
		assert.Equal(t, "bucket", bucket)
		assert.Equal(t, "object.key", objectKey)
	}

	bucket, objectKey, err = splitRemotePath("s3://some-bucket/some/path/to/object.foo")
	if assert.NoError(t, err) {
		assert.Equal(t, "some-bucket", bucket)
		assert.Equal(t, "some/path/to/object.foo", objectKey)
	}

	_, _, err = splitRemotePath("http://example.com/wibble.bar")
	assert.Error(t, err)
}

func TestRoundTripUploadDownload_withChecksum(t *testing.T) {
	backend := s3mem.New()
	faker := gofakes3.New(backend)
	ts := httptest.NewServer(faker.Server())
	defer ts.Close()

	expected, err := utils.Random(4096)
	require.NoError(t, err, "Cannot create file contents")

	uploadFile, err := utils.CreateTempFile("upload", expected)
	require.NoError(t, err, "Cannot create file to upload")
	defer os.Remove(uploadFile)

	accessKey := "AKIAIOSFODNN7EXAMPLE"
	secretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	target, err := NewS3(accessKey, secretKey, "", "us-east-1", ts.URL)
	require.NoError(t, err, "failed to create S3 client")

	impl := target.(*s3store)
	_, err = impl.api.CreateBucket(&s3.CreateBucketInput{Bucket: aws.String("test-bucket")})
	require.NoError(t, err, "failed to create bucket")

	err = target.UploadFile("s3://test-bucket/test-file", uploadFile, "wibble")
	require.NoError(t, err, "failed to upload file")

	downloadFile := uploadFile + ".download"
	checksum, err := target.DownloadFile("s3://test-bucket/test-file", downloadFile)
	require.NoError(t, err, "failed to download file")
	defer os.Remove(downloadFile)

	actual, err := ioutil.ReadFile(downloadFile)
	require.NoError(t, err, "Cannot read downloaded file")

	assert.Equal(t, "wibble", checksum)
	assert.Equal(t, expected, actual, "File contents are different")
}

func TestRoundTripUploadDownload_withoutChecksum(t *testing.T) {
	backend := s3mem.New()
	faker := gofakes3.New(backend)
	ts := httptest.NewServer(faker.Server())
	defer ts.Close()

	expected, err := utils.Random(4096)
	require.NoError(t, err, "Cannot create file contents")

	uploadFile, err := utils.CreateTempFile("upload", expected)
	require.NoError(t, err, "Cannot create file to upload")
	defer os.Remove(uploadFile)

	accessKey := "AKIAIOSFODNN7EXAMPLE"
	secretKey := "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	target, err := NewS3(accessKey, secretKey, "", "us-east-1", ts.URL)
	require.NoError(t, err, "failed to create S3 client")

	impl := target.(*s3store)
	_, err = impl.api.CreateBucket(&s3.CreateBucketInput{Bucket: aws.String("test-bucket")})
	require.NoError(t, err, "failed to create bucket")

	err = target.UploadFile("s3://test-bucket/test-file", uploadFile, "")
	require.NoError(t, err, "failed to upload file")

	downloadFile := uploadFile + ".download"
	checksum, err := target.DownloadFile("s3://test-bucket/test-file", downloadFile)
	require.NoError(t, err, "failed to download file")
	defer os.Remove(downloadFile)

	actual, err := ioutil.ReadFile(downloadFile)
	require.NoError(t, err, "Cannot read downloaded file")

	assert.Equal(t, "", checksum)
	assert.Equal(t, expected, actual, "File contents are different")
}
