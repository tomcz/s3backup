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

type Vault struct {
	Path       string
	IsKV2      bool
	Token      string
	Mount      string
	RoleID     string
	SecretID   string
	VaultAddr  string
	CaCertFile string
}

func (v Vault) Lookup(ctx context.Context) (*Config, error) {
	client, err := v.newClient()
	if err != nil {
		return nil, err
	}
	shouldLogout, err := v.login(ctx, client)
	if err != nil {
		return nil, err
	}
	defer func() {
		if shouldLogout {
			_, _ = client.Auth.TokenRevokeSelf(ctx)
		}
	}()
	return v.lookup(ctx, client)
}

func (v Vault) newClient() (*vault.Client, error) {
	opts := []vault.ClientOption{vault.WithEnvironment()}
	if v.VaultAddr != "" {
		opts = append(opts, vault.WithAddress(v.VaultAddr))
	}
	if v.CaCertFile != "" {
		opts = append(opts, vault.WithTLS(vault.TLSConfiguration{
			ServerCertificate: vault.ServerCertificateEntry{
				FromFile: v.CaCertFile,
			},
		}))
	}
	client, err := vault.New(opts...)
	if err != nil {
		return nil, fmt.Errorf("vault.New: %w", err)
	}
	return client, nil
}

func (v Vault) login(ctx context.Context, client *vault.Client) (bool, error) {
	if v.Token != "" {
		log.Println("Authenticating with vault using token")
		if err := client.SetToken(v.Token); err != nil {
			return false, fmt.Errorf("vault.SetToken: %w", err)
		}
		return false, nil
	}
	if v.RoleID != "" && v.SecretID != "" {
		log.Println("Authenticating with vault using approle credentials")
		var opts []vault.RequestOption
		if v.Mount != "" {
			opts = append(opts, vault.WithMountPath(v.Mount))
		}
		req := schema.AppRoleLoginRequest{
			RoleId:   v.RoleID,
			SecretId: v.SecretID,
		}
		resp, err := client.Auth.AppRoleLogin(ctx, req, opts...)
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

func (v Vault) lookup(ctx context.Context, client *vault.Client) (*Config, error) {
	log.Println("Fetching configuration from vault")
	secret, err := client.Read(ctx, v.Path)
	if err != nil {
		return nil, fmt.Errorf("vault.Read: %w", responseError(err))
	}
	data := v.getData(secret)
	if data == nil {
		return nil, fmt.Errorf("secret not found at path %q", v.Path)
	}
	var cfg Config
	if err = mapstructure.Decode(data, &cfg); err != nil {
		return nil, fmt.Errorf("secret.Decode: %w", err)
	}
	return &cfg, nil
}

func (v Vault) getData(secret *vault.Response[map[string]interface{}]) any {
	if secret == nil || secret.Data == nil {
		return nil
	}
	if v.IsKV2 {
		return secret.Data["data"]
	}
	return secret.Data
}

func responseError(err error) error {
	var verr *vault.ResponseError
	if errors.As(err, &verr) && verr.OriginalRequest != nil {
		return fmt.Errorf("%s %s: %w", verr.OriginalRequest.Method, verr.OriginalRequest.URL.String(), err)
	}
	return err
}
