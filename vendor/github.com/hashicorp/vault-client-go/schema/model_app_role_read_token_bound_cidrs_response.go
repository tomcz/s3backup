// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// AppRoleReadTokenBoundCidrsResponse struct for AppRoleReadTokenBoundCidrsResponse
type AppRoleReadTokenBoundCidrsResponse struct {
	// Comma separated string or list of CIDR blocks. If set, specifies the blocks of IP addresses which can use the returned token. Should be a subset of the token CIDR blocks listed on the role, if any.
	TokenBoundCidrs []string `json:"token_bound_cidrs,omitempty"`
}

// NewAppRoleReadTokenBoundCidrsResponseWithDefaults instantiates a new AppRoleReadTokenBoundCidrsResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppRoleReadTokenBoundCidrsResponseWithDefaults() *AppRoleReadTokenBoundCidrsResponse {
	var this AppRoleReadTokenBoundCidrsResponse

	return &this
}
