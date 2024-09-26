package main

import (
	"testing"

	"gotest.tools/v3/assert"
)

func TestCheckPaths(t *testing.T) {
	localPath = "s3://foo/bar.txt"
	remotePath = "s3://foo/bar.txt"
	assert.Error(t, checkPaths(), "cannot have two remote paths")

	localPath = "bar.txt"
	remotePath = "bar.txt"
	assert.Error(t, checkPaths(), "cannot have two local paths")

	localPath = "bar.txt"
	remotePath = "s3://foo/bar.txt"
	assert.NilError(t, checkPaths())

	localPath = "s3://foo/bar.txt"
	remotePath = "bar.txt"
	assert.NilError(t, checkPaths())
	assert.Equal(t, "bar.txt", localPath)
	assert.Equal(t, "s3://foo/bar.txt", remotePath)
}
