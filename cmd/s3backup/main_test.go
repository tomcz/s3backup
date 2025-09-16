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

func TestJsonConfig_VaultPut(t *testing.T) {
	var app appCfg
	parser, err := kong.New(&app, kong.Configuration(kong.JSON, "testdata/vault_put.json"))
	assert.NilError(t, err)
	_, err = parser.Parse([]string{"vault-put", "local", "remote"})
	assert.NilError(t, err)
	assert.Equal(t, app.VaultPut.LocalPath, "local")
	assert.Equal(t, app.VaultPut.RemotePath, "remote")
	assert.Equal(t, app.VaultPut.SkipHash, true)
	assert.Equal(t, app.VaultPut.Path, "secret/data/wibble/wobble")
	assert.Equal(t, app.VaultPut.IsKV2, true)
	assert.Equal(t, app.VaultPut.Mount, "waggle")
	assert.Equal(t, app.VaultPut.RoleID, "test_role_id")
	assert.Equal(t, app.VaultPut.SecretID, "test_secret_id")
	assert.Equal(t, app.VaultPut.Token, "test_token")
	assert.Equal(t, app.VaultPut.CaCert, "test_cert_path")
	assert.Equal(t, app.VaultPut.Address, "test_vault_url")
}

func TestJsonConfig_VaultGet(t *testing.T) {
	var app appCfg
	parser, err := kong.New(&app, kong.Configuration(kong.JSON, "testdata/vault_get.json"))
	assert.NilError(t, err)
	_, err = parser.Parse([]string{"vault-get", "remote", "local"})
	assert.NilError(t, err)
	assert.Equal(t, app.VaultGet.LocalPath, "local")
	assert.Equal(t, app.VaultGet.RemotePath, "remote")
	assert.Equal(t, app.VaultGet.SkipHash, false)
	assert.Equal(t, app.VaultGet.Path, "secret/wibble/wobble")
	assert.Equal(t, app.VaultGet.IsKV2, false)
	assert.Equal(t, app.VaultGet.Mount, "")
	assert.Equal(t, app.VaultGet.RoleID, "test_role_id")
	assert.Equal(t, app.VaultGet.SecretID, "test_secret_id")
	assert.Equal(t, app.VaultGet.Token, "")
	assert.Equal(t, app.VaultGet.CaCert, "")
	assert.Equal(t, app.VaultGet.Address, "test_vault_url")
}
