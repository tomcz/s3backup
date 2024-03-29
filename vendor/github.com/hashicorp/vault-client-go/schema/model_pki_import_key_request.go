// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// PkiImportKeyRequest struct for PkiImportKeyRequest
type PkiImportKeyRequest struct {
	// Optional name to be used for this key
	KeyName string `json:"key_name,omitempty"`

	// PEM-format, unencrypted secret key
	PemBundle string `json:"pem_bundle,omitempty"`
}

// NewPkiImportKeyRequestWithDefaults instantiates a new PkiImportKeyRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewPkiImportKeyRequestWithDefaults() *PkiImportKeyRequest {
	var this PkiImportKeyRequest

	return &this
}
