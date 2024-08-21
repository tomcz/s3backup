package config

import (
	"context"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/tomcz/s3backup/v2/internal/utils"
)

const loginJSON = `{
  "auth": {
    "renewable": true,
    "lease_duration": 1200,
    "metadata": null,
    "policies": [
      "default"
    ],
    "accessor": "fd6c9a00-d2dc-3b11-0be5-af7ae0e1d374",
    "client_token": "5b1a0318-679c-9c45-e5c6-d1b9a9035d49"
  },
  "warnings": null,
  "wrap_info": null,
  "data": null,
  "lease_duration": 0,
  "renewable": false,
  "lease_id": ""
}`

const secretJSON = `{
  "auth": null,
  "data": {
    "cipher_key": "use me to encrypt",
    "s3_access_key": "aws access",
    "s3_secret_key": "aws secret",
    "s3_token": "aws token",
    "s3_region": "us-west-2",
    "s3_endpoint": "https://spaces.test"
  },
  "lease_duration": 2764800,
  "lease_id": "",
  "renewable": false
}`

func checkLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, fmt.Sprintf("checkLogin: bad method: %s", r.Method), http.StatusMethodNotAllowed)
		return
	}
	var m map[string]any
	if err := json.NewDecoder(r.Body).Decode(&m); err != nil {
		http.Error(w, fmt.Sprintf("checkLogin: %v", err), http.StatusInternalServerError)
		return
	}
	role := m["role_id"].(string)
	secret := m["secret_id"].(string)
	if role != "test-role" || secret != "test-secret" {
		http.Error(w, "checkLogin: unknown role/secret IDs", http.StatusForbidden)
		return
	}
	fmt.Fprintln(w, loginJSON)
}

func respondWith(body string) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			http.Error(w, fmt.Sprintf("respondWith: bad method: %s", r.Method), http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("X-Vault-Token") != "5b1a0318-679c-9c45-e5c6-d1b9a9035d49" {
			http.Error(w, "respondWith: bad token", http.StatusForbidden)
			return
		}
		fmt.Fprintln(w, body)
	}
}

func testHandler() http.Handler {
	r := http.NewServeMux()
	r.HandleFunc("/v1/auth/approle/login", checkLogin)
	r.HandleFunc("/v1/secret/myteam/backup", respondWith(secretJSON))
	return r
}

func TestLookupWithAppRole(t *testing.T) {
	ts := httptest.NewServer(testHandler())
	defer ts.Close()

	ctx := context.Background()
	cfg, err := LookupWithAppRole(ctx, ts.URL, "", "test-role", "test-secret", "secret/myteam/backup")
	assert.NilError(t, err)

	assert.Equal(t, "use me to encrypt", cfg.CipherKey)
	assert.Equal(t, "aws access", cfg.S3AccessKey)
	assert.Equal(t, "aws secret", cfg.S3SecretKey)
	assert.Equal(t, "aws token", cfg.S3Token)
	assert.Equal(t, "us-west-2", cfg.S3Region)
	assert.Equal(t, "https://spaces.test", cfg.S3Endpoint)
}

func TestLookupWithToken(t *testing.T) {
	ts := httptest.NewTLSServer(testHandler())
	defer ts.Close()

	cert := ts.Certificate()
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	certFile, err := utils.CreateTempFile("vault", encoded)
	assert.NilError(t, err)

	ctx := context.Background()
	cfg, err := LookupWithToken(ctx, ts.URL, certFile, "5b1a0318-679c-9c45-e5c6-d1b9a9035d49", "secret/myteam/backup")
	assert.NilError(t, err)

	assert.Equal(t, "use me to encrypt", cfg.CipherKey)
	assert.Equal(t, "aws access", cfg.S3AccessKey)
	assert.Equal(t, "aws secret", cfg.S3SecretKey)
	assert.Equal(t, "aws token", cfg.S3Token)
	assert.Equal(t, "us-west-2", cfg.S3Region)
	assert.Equal(t, "https://spaces.test", cfg.S3Endpoint)
}
