// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// PkiWriteKeyResponse struct for PkiWriteKeyResponse
type PkiWriteKeyResponse struct {
	// Key Id
	KeyId string `json:"key_id,omitempty"`

	// Key Name
	KeyName string `json:"key_name,omitempty"`

	// Key Type
	KeyType string `json:"key_type,omitempty"`
}

// NewPkiWriteKeyResponseWithDefaults instantiates a new PkiWriteKeyResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewPkiWriteKeyResponseWithDefaults() *PkiWriteKeyResponse {
	var this PkiWriteKeyResponse

	return &this
}
