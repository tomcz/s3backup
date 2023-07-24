package config

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
	"github.com/mitchellh/mapstructure"
)

func LookupWithAppRole(ctx context.Context, vaultAddr, caCertFile, roleID, secretID, path string) (*Config, error) {
	client, err := newClient(vaultAddr, caCertFile)
	if err != nil {
		return nil, err
	}
	resp, err := client.Auth.AppRoleLogin(ctx, schema.AppRoleLoginRequest{RoleId: roleID, SecretId: secretID})
	if err != nil {
		return nil, err
	}
	if err = client.SetToken(resp.Auth.ClientToken); err != nil {
		return nil, err
	}
	defer logout(ctx, client, resp.Auth.Renewable)
	return lookup(ctx, client, path)
}

func LookupWithToken(ctx context.Context, vaultAddr, caCertFile, token, path string) (*Config, error) {
	client, err := newClient(vaultAddr, caCertFile)
	if err != nil {
		return nil, err
	}
	if err = client.SetToken(token); err != nil {
		return nil, err
	}
	return lookup(ctx, client, path)
}

func newClient(vaultAddr, caCertFile string) (*vault.Client, error) {
	var opts []vault.ClientOption
	if vaultAddr != "" {
		opts = append(opts, vault.WithAddress(vaultAddr))
	}
	if caCertFile != "" {
		opts = append(opts, vault.WithTLS(vault.TLSConfiguration{
			ServerCertificate: vault.ServerCertificateEntry{
				FromFile: caCertFile,
			},
		}))
	}
	return vault.New(opts...)
}

func lookup(ctx context.Context, client *vault.Client, path string) (*Config, error) {
	secret, err := client.Read(ctx, path)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, fmt.Errorf("secret not found at path %q", path)
	}
	var cfg Config
	if err = mapstructure.Decode(secret.Data, &cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func logout(ctx context.Context, client *vault.Client, shouldLogout bool) {
	if shouldLogout {
		client.Auth.TokenRevokeSelf(ctx) //nolint:all
	}
}
