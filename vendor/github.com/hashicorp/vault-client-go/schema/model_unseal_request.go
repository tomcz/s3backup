// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// UnsealRequest struct for UnsealRequest
type UnsealRequest struct {
	// Specifies a single unseal key share. This is required unless reset is true.
	Key string `json:"key,omitempty"`

	// Specifies if previously-provided unseal keys are discarded and the unseal process is reset.
	Reset bool `json:"reset,omitempty"`
}

// NewUnsealRequestWithDefaults instantiates a new UnsealRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewUnsealRequestWithDefaults() *UnsealRequest {
	var this UnsealRequest

	return &this
}
