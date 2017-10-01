package config

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"

	"io/ioutil"
)

type Vault interface {
	LookupWithIDs(roleID, secretID, path string) (*Config, error)
	LookupWithToken(token, path string) (*Config, error)
}

type vault struct {
	client    *http.Client
	vaultAddr string
}

func NewVault(vaultAddr, caCertFile string) (Vault, error) {
	var client *http.Client
	if caCertFile != "" {
		certBytes, err := ioutil.ReadFile(caCertFile)
		if err != nil {
			return nil, err
		}
		certPool := x509.NewCertPool()
		certPool.AppendCertsFromPEM(certBytes)
		tlsConfig := &tls.Config{RootCAs: certPool}
		transport := &http.Transport{TLSClientConfig: tlsConfig}
		client = &http.Client{Transport: transport}
	} else {
		client = &http.Client{}
	}
	return &vault{
		client:    client,
		vaultAddr: vaultAddr,
	}, nil
}

func (v *vault) LookupWithIDs(roleID, secretID, path string) (*Config, error) {
	body := map[string]string{
		"role_id":   roleID,
		"secret_id": secretID,
	}

	buf, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	url := v.urlFor("auth/approle/login")
	res, err := v.client.Post(url, "application/json", bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if failed(res.StatusCode) {
		return nil, fmt.Errorf("failed POST %v: %v", url, res.Status)
	}

	m := make(map[string]interface{})
	if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
		return nil, err
	}

	token := get(m, "auth", "client_token")
	return v.LookupWithToken(token, path)
}

func (v *vault) LookupWithToken(token, path string) (*Config, error) {
	url := v.urlFor(path)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", token)

	res, err := v.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()

	if failed(res.StatusCode) {
		return nil, fmt.Errorf("failed GET %v: %v", url, res.Status)
	}

	m := make(map[string]interface{})
	if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
		return nil, err
	}

	return &Config{
		CipherKey:   get(m, "data", "cipher_key"),
		S3AccessKey: get(m, "data", "s3_access_key"),
		S3SecretKey: get(m, "data", "s3_secret_key"),
		S3Token:     get(m, "data", "s3_token"),
		S3Region:    get(m, "data", "s3_region"),
		S3Endpoint:  get(m, "data", "s3_endpoint"),
	}, nil
}

func (v *vault) urlFor(path string) string {
	return fmt.Sprintf("%v/v1/%v", v.vaultAddr, path)
}

func failed(status int) bool {
	return status < 200 || status > 299
}

func get(m map[string]interface{}, path ...string) string {
	end := len(path) - 1
	for i, key := range path {
		val, ok := m[key]
		if !ok {
			return ""
		}
		if i != end {
			m = val.(map[string]interface{})
		} else {
			return val.(string)
		}
	}
	return ""
}
