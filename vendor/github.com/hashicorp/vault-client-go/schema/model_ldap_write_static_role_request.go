// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// LdapWriteStaticRoleRequest struct for LdapWriteStaticRoleRequest
type LdapWriteStaticRoleRequest struct {
	// The distinguished name of the entry to manage.
	Dn string `json:"dn,omitempty"`

	// Period for automatic credential rotation of the given entry.
	RotationPeriod int32 `json:"rotation_period,omitempty"`

	// The username/logon name for the entry with which this role will be associated.
	Username string `json:"username,omitempty"`
}

// NewLdapWriteStaticRoleRequestWithDefaults instantiates a new LdapWriteStaticRoleRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewLdapWriteStaticRoleRequestWithDefaults() *LdapWriteStaticRoleRequest {
	var this LdapWriteStaticRoleRequest

	return &this
}
