// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// PkiGenerateKmsKeyResponse struct for PkiGenerateKmsKeyResponse
type PkiGenerateKmsKeyResponse struct {
	// ID assigned to this key.
	KeyId string `json:"key_id,omitempty"`

	// Name assigned to this key.
	KeyName string `json:"key_name,omitempty"`

	// The type of key to use; defaults to RSA. \"rsa\" \"ec\" and \"ed25519\" are the only valid values.
	KeyType string `json:"key_type,omitempty"`

	// The private key string
	PrivateKey string `json:"private_key,omitempty"`
}

// NewPkiGenerateKmsKeyResponseWithDefaults instantiates a new PkiGenerateKmsKeyResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewPkiGenerateKmsKeyResponseWithDefaults() *PkiGenerateKmsKeyResponse {
	var this PkiGenerateKmsKeyResponse

	return &this
}
