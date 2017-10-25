package config

import (
	"fmt"

	"github.com/hashicorp/vault/api"
)

type Vault interface {
	LookupWithAppRole(roleID, secretID, path string) (*Config, error)
	LookupWithToken(token, path string) (*Config, error)
}

type vault struct {
	client *api.Client
}

func NewVault(vaultAddr, caCertFile string) (Vault, error) {
	cfg := api.DefaultConfig()
	if err := cfg.ReadEnvironment(); err != nil {
		return nil, err
	}
	if vaultAddr != "" {
		cfg.Address = vaultAddr
	}
	if caCertFile != "" {
		t := &api.TLSConfig{CACert: caCertFile}
		if err := cfg.ConfigureTLS(t); err != nil {
			return nil, err
		}
	}
	client, err := api.NewClient(cfg)
	if err != nil {
		return nil, err
	}
	return &vault{client}, nil
}

func (v *vault) LookupWithAppRole(roleID, secretID, path string) (*Config, error) {
	body := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}
	secret, err := v.client.Logical().Write("auth/approle/login", body)
	if err != nil {
		return nil, err
	}
	return v.LookupWithToken(secret.Auth.ClientToken, path)
}

func (v *vault) LookupWithToken(token, path string) (*Config, error) {
	if token != "" {
		v.client.SetToken(token)
	}
	secret, err := v.client.Logical().Read(path)
	if err != nil {
		return nil, err
	}
	return &Config{
		CipherKey:   get(secret.Data, "cipher_key"),
		S3AccessKey: get(secret.Data, "s3_access_key"),
		S3SecretKey: get(secret.Data, "s3_secret_key"),
		S3Token:     get(secret.Data, "s3_token"),
		S3Region:    get(secret.Data, "s3_region"),
		S3Endpoint:  get(secret.Data, "s3_endpoint"),
	}, nil
}

func get(m map[string]interface{}, key string) string {
	val, ok := m[key]
	if !ok {
		return ""
	}
	return fmt.Sprint(val)
}
