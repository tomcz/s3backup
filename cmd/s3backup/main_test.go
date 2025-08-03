package main

import (
	"testing"

	"gotest.tools/v3/assert"
)

func TestCheckPaths(t *testing.T) {
	inLocal := "s3://foo/bar.txt"
	inRemote := "s3://foo/bar.txt"
	_, _, err := checkPaths(inRemote, inLocal)
	assert.Error(t, err, "cannot have two remote paths")

	inLocal = "bar.txt"
	inRemote = "bar.txt"
	_, _, err = checkPaths(inRemote, inLocal)
	assert.Error(t, err, "cannot have two local paths")

	inLocal = "bar.txt"
	inRemote = "s3://foo/bar.txt"
	outRemote, outLocal, err := checkPaths(inRemote, inLocal)
	assert.NilError(t, err)
	assert.Equal(t, inLocal, outLocal)
	assert.Equal(t, inRemote, outRemote)

	inLocal = "s3://foo/bar.txt"
	inRemote = "bar.txt"
	outRemote, outLocal, err = checkPaths(inRemote, inLocal)
	assert.NilError(t, err)
	assert.Equal(t, inLocal, outRemote)
	assert.Equal(t, inRemote, outLocal)
}
