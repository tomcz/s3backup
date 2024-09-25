package main

import (
	"testing"

	"gotest.tools/v3/assert"
)

func TestCheckPaths(t *testing.T) {
	localPath = "bar.txt"
	remotePath = "s3://foo/bar.txt"
	assert.NilError(t, checkPaths())
	localPath = "s3://foo/bar.txt"
	remotePath = "bar.txt"
	assert.NilError(t, checkPaths())
	assert.Equal(t, "bar.txt", localPath)
	assert.Equal(t, "s3://foo/bar.txt", remotePath)
}
