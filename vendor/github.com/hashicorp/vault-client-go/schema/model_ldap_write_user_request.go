// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// LdapWriteUserRequest struct for LdapWriteUserRequest
type LdapWriteUserRequest struct {
	// Comma-separated list of additional groups associated with the user.
	Groups []string `json:"groups,omitempty"`

	// Comma-separated list of policies associated with the user.
	Policies []string `json:"policies,omitempty"`
}

// NewLdapWriteUserRequestWithDefaults instantiates a new LdapWriteUserRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewLdapWriteUserRequestWithDefaults() *LdapWriteUserRequest {
	var this LdapWriteUserRequest

	return &this
}
