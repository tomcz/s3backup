package main

import (
	"testing"

	"github.com/alecthomas/kong"
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

func TestJsonConfig_Get(t *testing.T) {
	var app appCfg
	parser, err := kong.New(&app, kong.Configuration(kong.JSON, "testdata/get.json"))
	assert.NilError(t, err)
	_, err = parser.Parse([]string{"get", "remote", "local"})
	assert.NilError(t, err)
	assert.Equal(t, app.Get.LocalPath, "local")
	assert.Equal(t, app.Get.RemotePath, "remote")
	assert.Equal(t, app.Get.SkipHash, true)
	assert.Equal(t, app.Get.SymKey, "wibble")
	assert.Equal(t, app.Get.PemKey, "")
	assert.Equal(t, app.Get.AccessKey, "test_accessKey")
	assert.Equal(t, app.Get.SecretKey, "test_secretKey")
	assert.Equal(t, app.Get.Token, "test_token")
	assert.Equal(t, app.Get.Region, "test_region")
	assert.Equal(t, app.Get.Endpoint, "test_endpoint")
}

func TestJsonConfig_Put(t *testing.T) {
	var app appCfg
	parser, err := kong.New(&app, kong.Configuration(kong.JSON, "testdata/put.json"))
	assert.NilError(t, err)
	_, err = parser.Parse([]string{"put", "local", "remote"})
	assert.NilError(t, err)
	assert.Equal(t, app.Put.LocalPath, "local")
	assert.Equal(t, app.Put.RemotePath, "remote")
	assert.Equal(t, app.Put.SkipHash, false)
	assert.Equal(t, app.Put.SymKey, "")
	assert.Equal(t, app.Put.PemKey, "wobble")
	assert.Equal(t, app.Put.AccessKey, "test_accessKey")
	assert.Equal(t, app.Put.SecretKey, "test_secretKey")
	assert.Equal(t, app.Put.Token, "test_token")
	assert.Equal(t, app.Put.Region, "test_region")
	assert.Equal(t, app.Put.Endpoint, "test_endpoint")
}
