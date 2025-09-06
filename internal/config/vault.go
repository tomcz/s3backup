package config

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

func LookupWithAppRole(ctx context.Context, vaultAddr, caCertFile, roleID, secretID, path string) (*Config, error) {
	client, err := newClient(vaultAddr, caCertFile)
	if err != nil {
		return nil, fmt.Errorf("approle.Client: %w", err)
	}
	resp, err := client.Auth.AppRoleLogin(ctx, schema.AppRoleLoginRequest{RoleId: roleID, SecretId: secretID})
	if err != nil {
		var verr *vault.ResponseError
		if errors.As(err, &verr) && verr.OriginalRequest != nil {
			return nil, expandError(verr.OriginalRequest, err)
		}
		return nil, fmt.Errorf("approle.Login: %w", err)
	}
	if err = client.SetToken(resp.Auth.ClientToken); err != nil {
		return nil, fmt.Errorf("approle.SetToken: %w", err)
	}
	defer logout(ctx, client, resp.Auth.Renewable)
	return lookup(ctx, client, path)
}

func LookupWithToken(ctx context.Context, vaultAddr, caCertFile, token, path string) (*Config, error) {
	client, err := newClient(vaultAddr, caCertFile)
	if err != nil {
		return nil, fmt.Errorf("token.Client: %w", err)
	}
	if err = client.SetToken(token); err != nil {
		return nil, fmt.Errorf("token.SetToken: %w", err)
	}
	return lookup(ctx, client, path)
}

func newClient(vaultAddr, caCertFile string) (*vault.Client, error) {
	opts := []vault.ClientOption{vault.WithEnvironment()}
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
		var verr *vault.ResponseError
		if errors.As(err, &verr) && verr.OriginalRequest != nil {
			return nil, expandError(verr.OriginalRequest, err)
		}
		return nil, fmt.Errorf("vault.Read: %w", err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("secret not found at path %q", path)
	}
	var cfg Config
	if err = mapstructure.Decode(secret.Data, &cfg); err != nil {
		return nil, fmt.Errorf("secret.Decode: %w", err)
	}
	return &cfg, nil
}

func expandError(req *http.Request, err error) error {
	return fmt.Errorf("%s %s: %w", req.Method, req.URL.String(), err)
}

func logout(ctx context.Context, client *vault.Client, shouldLogout bool) {
	if shouldLogout {
		_, _ = client.Auth.TokenRevokeSelf(ctx)
	}
}
