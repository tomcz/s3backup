// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// AppRoleWriteTokenBoundCidrsRequest struct for AppRoleWriteTokenBoundCidrsRequest
type AppRoleWriteTokenBoundCidrsRequest struct {
	// Comma separated string or JSON list of CIDR blocks. If set, specifies the blocks of IP addresses which are allowed to use the generated token.
	TokenBoundCidrs []string `json:"token_bound_cidrs,omitempty"`
}

// NewAppRoleWriteTokenBoundCidrsRequestWithDefaults instantiates a new AppRoleWriteTokenBoundCidrsRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppRoleWriteTokenBoundCidrsRequestWithDefaults() *AppRoleWriteTokenBoundCidrsRequest {
	var this AppRoleWriteTokenBoundCidrsRequest

	return &this
}
