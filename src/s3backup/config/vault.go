package config

import (
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
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
	var cfg Config
	if err = mapstructure.Decode(secret.Data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}
