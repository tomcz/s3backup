// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// GoogleCloudGenerateRolesetKeyWithParametersRequest struct for GoogleCloudGenerateRolesetKeyWithParametersRequest
type GoogleCloudGenerateRolesetKeyWithParametersRequest struct {
	// Private key algorithm for service account key - defaults to KEY_ALG_RSA_2048\"
	KeyAlgorithm string `json:"key_algorithm,omitempty"`

	// Private key type for service account key - defaults to TYPE_GOOGLE_CREDENTIALS_FILE\"
	KeyType string `json:"key_type,omitempty"`

	// Lifetime of the service account key
	Ttl int32 `json:"ttl,omitempty"`
}

// NewGoogleCloudGenerateRolesetKeyWithParametersRequestWithDefaults instantiates a new GoogleCloudGenerateRolesetKeyWithParametersRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewGoogleCloudGenerateRolesetKeyWithParametersRequestWithDefaults() *GoogleCloudGenerateRolesetKeyWithParametersRequest {
	var this GoogleCloudGenerateRolesetKeyWithParametersRequest

	this.KeyAlgorithm = "KEY_ALG_RSA_2048"
	this.KeyType = "TYPE_GOOGLE_CREDENTIALS_FILE"

	return &this
}
