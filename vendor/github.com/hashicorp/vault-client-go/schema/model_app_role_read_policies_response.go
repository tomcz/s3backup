// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// AppRoleReadPoliciesResponse struct for AppRoleReadPoliciesResponse
type AppRoleReadPoliciesResponse struct {
	// Use \"token_policies\" instead. If this and \"token_policies\" are both specified, only \"token_policies\" will be used.
	// Deprecated
	Policies []string `json:"policies,omitempty"`

	// Comma-separated list of policies
	TokenPolicies []string `json:"token_policies,omitempty"`
}

// NewAppRoleReadPoliciesResponseWithDefaults instantiates a new AppRoleReadPoliciesResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppRoleReadPoliciesResponseWithDefaults() *AppRoleReadPoliciesResponse {
	var this AppRoleReadPoliciesResponse

	return &this
}
