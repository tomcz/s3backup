package config

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/go-viper/mapstructure/v2"
	"github.com/hashicorp/vault-client-go"
	"github.com/hashicorp/vault-client-go/schema"
)

type VaultOpts struct {
	Path       string
	Token      string
	RoleID     string
	SecretID   string
	VaultAddr  string
	CaCertFile string
}

func Lookup(ctx context.Context, opts VaultOpts) (*Config, error) {
	client, err := newClient(opts.VaultAddr, opts.CaCertFile)
	if err != nil {
		return nil, err
	}
	shouldLogout, err := login(ctx, client, opts.Token, opts.RoleID, opts.SecretID)
	if err != nil {
		return nil, err
	}
	defer func() {
		if shouldLogout {
			_, _ = client.Auth.TokenRevokeSelf(ctx)
		}
	}()
	return lookup(ctx, client, opts.Path)
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
	client, err := vault.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("vault.New: %w", err)
	}
	return client, nil
}

func login(ctx context.Context, client *vault.Client, token, roleID, secretID string) (bool, error) {
	if token != "" {
		log.Println("Authenticating with vault using token")
		if err := client.SetToken(token); err != nil {
			return false, fmt.Errorf("vault.SetToken: %w", err)
		}
		return false, nil
	}
	if roleID != "" && secretID != "" {
		log.Println("Authenticating with vault using approle credentials")
		resp, err := client.Auth.AppRoleLogin(ctx, schema.AppRoleLoginRequest{RoleId: roleID, SecretId: secretID})
		if err != nil {
			return false, fmt.Errorf("approle.Login: %w", responseError(err))
		}
		if err = client.SetToken(resp.Auth.ClientToken); err != nil {
			return false, fmt.Errorf("approle.SetToken: %w", err)
		}
		return resp.Auth.Renewable, nil
	}
	return false, errors.New("vault credentials not provided")
}

func lookup(ctx context.Context, client *vault.Client, path string) (*Config, error) {
	log.Println("Fetching configuration from vault")
	secret, err := client.Read(ctx, path)
	if err != nil {
		return nil, fmt.Errorf("vault.Read: %w", responseError(err))
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

func responseError(err error) error {
	var verr *vault.ResponseError
	if errors.As(err, &verr) && verr.OriginalRequest != nil {
		return fmt.Errorf("%s %s: %w", verr.OriginalRequest.Method, verr.OriginalRequest.URL.String(), err)
	}
	return err
}
