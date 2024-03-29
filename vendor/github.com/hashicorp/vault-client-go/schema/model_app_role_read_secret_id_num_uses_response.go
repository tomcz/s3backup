// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// AppRoleReadSecretIdNumUsesResponse struct for AppRoleReadSecretIdNumUsesResponse
type AppRoleReadSecretIdNumUsesResponse struct {
	// Number of times a secret ID can access the role, after which the SecretID will expire. Defaults to 0 meaning that the secret ID is of unlimited use.
	SecretIdNumUses int32 `json:"secret_id_num_uses,omitempty"`
}

// NewAppRoleReadSecretIdNumUsesResponseWithDefaults instantiates a new AppRoleReadSecretIdNumUsesResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppRoleReadSecretIdNumUsesResponseWithDefaults() *AppRoleReadSecretIdNumUsesResponse {
	var this AppRoleReadSecretIdNumUsesResponse

	return &this
}
