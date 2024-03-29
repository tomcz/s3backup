// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// OidcWriteScopeRequest struct for OidcWriteScopeRequest
type OidcWriteScopeRequest struct {
	// The description of the scope
	Description string `json:"description,omitempty"`

	// The template string to use for the scope. This may be in string-ified JSON or base64 format.
	Template string `json:"template,omitempty"`
}

// NewOidcWriteScopeRequestWithDefaults instantiates a new OidcWriteScopeRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewOidcWriteScopeRequestWithDefaults() *OidcWriteScopeRequest {
	var this OidcWriteScopeRequest

	return &this
}
