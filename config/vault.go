package config

import (
	"github.com/hashicorp/vault/api"
	"github.com/mitchellh/mapstructure"
)

func LookupWithAppRole(vaultAddr, caCertFile, roleID, secretID, path string) (*Config, error) {
	client, err := newClient(vaultAddr, caCertFile)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"role_id": roleID, "secret_id": secretID}
	secret, err := client.Logical().Write("auth/approle/login", body)
	if err != nil {
		return nil, err
	}
	client.SetToken(secret.Auth.ClientToken)
	defer logout(client, secret.Auth.Renewable)
	return lookup(client, path)
}

func LookupWithToken(vaultAddr, caCertFile, token, path string) (*Config, error) {
	client, err := newClient(vaultAddr, caCertFile)
	if err != nil {
		return nil, err
	}
	client.SetToken(token)
	return lookup(client, path)
}

func newClient(vaultAddr, caCertFile string) (*api.Client, error) {
	cfg := api.DefaultConfig()
	if err := cfg.Error; err != nil {
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
	return api.NewClient(cfg)
}

func lookup(client *api.Client, path string) (*Config, error) {
	secret, err := client.Logical().Read(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err = mapstructure.Decode(secret.Data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func logout(client *api.Client, shouldLogout bool) {
	if shouldLogout {
		client.Auth().Token().RevokeSelf("") //nolint:all
	}
}
