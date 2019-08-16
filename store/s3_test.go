package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
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
