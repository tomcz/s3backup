package store

import (
	"testing"

	"gotest.tools/v3/assert"
)

func TestSplitRemotePath(t *testing.T) {
	bucket, objectKey, err := splitRemotePath("s3://bucket/object.key")
	assert.NilError(t, err)
	assert.Equal(t, "bucket", bucket)
	assert.Equal(t, "object.key", objectKey)

	bucket, objectKey, err = splitRemotePath("s3://some-bucket/some/path/to/object.foo")
	assert.NilError(t, err)
	assert.Equal(t, "some-bucket", bucket)
	assert.Equal(t, "some/path/to/object.foo", objectKey)

	_, _, err = splitRemotePath("http://example.com/wibble.bar")
	assert.ErrorContains(t, err, "not a valid S3 path")
}

func TestIsRemote(t *testing.T) {
	assert.Assert(t, IsRemote("s3://bucket/object.key"))
	assert.Assert(t, !IsRemote("wibble.txt"))
}
