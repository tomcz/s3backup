// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// AliCloudWriteAuthRoleRequest struct for AliCloudWriteAuthRoleRequest
type AliCloudWriteAuthRoleRequest struct {
	// ARN of the RAM to bind to this role.
	Arn string `json:"arn,omitempty"`

	// Use \"token_bound_cidrs\" instead. If this and \"token_bound_cidrs\" are both specified, only \"token_bound_cidrs\" will be used.
	// Deprecated
	BoundCidrs []string `json:"bound_cidrs,omitempty"`

	// Use \"token_max_ttl\" instead. If this and \"token_max_ttl\" are both specified, only \"token_max_ttl\" will be used.
	// Deprecated
	MaxTtl int32 `json:"max_ttl,omitempty"`

	// Use \"token_period\" instead. If this and \"token_period\" are both specified, only \"token_period\" will be used.
	// Deprecated
	Period int32 `json:"period,omitempty"`

	// Use \"token_policies\" instead. If this and \"token_policies\" are both specified, only \"token_policies\" will be used.
	// Deprecated
	Policies []string `json:"policies,omitempty"`

	// Comma separated string or JSON list of CIDR blocks. If set, specifies the blocks of IP addresses which are allowed to use the generated token.
	TokenBoundCidrs []string `json:"token_bound_cidrs,omitempty"`

	// If set, tokens created via this role carry an explicit maximum TTL. During renewal, the current maximum TTL values of the role and the mount are not checked for changes, and any updates to these values will have no effect on the token being renewed.
	TokenExplicitMaxTtl int32 `json:"token_explicit_max_ttl,omitempty"`

	// The maximum lifetime of the generated token
	TokenMaxTtl int32 `json:"token_max_ttl,omitempty"`

	// If true, the 'default' policy will not automatically be added to generated tokens
	TokenNoDefaultPolicy bool `json:"token_no_default_policy,omitempty"`

	// The maximum number of times a token may be used, a value of zero means unlimited
	TokenNumUses int32 `json:"token_num_uses,omitempty"`

	// If set, tokens created via this role will have no max lifetime; instead, their renewal period will be fixed to this value. This takes an integer number of seconds, or a string duration (e.g. \"24h\").
	TokenPeriod int32 `json:"token_period,omitempty"`

	// Comma-separated list of policies
	TokenPolicies []string `json:"token_policies,omitempty"`

	// The initial ttl of the token to generate
	TokenTtl int32 `json:"token_ttl,omitempty"`

	// The type of token to generate, service or batch
	TokenType string `json:"token_type,omitempty"`

	// Use \"token_ttl\" instead. If this and \"token_ttl\" are both specified, only \"token_ttl\" will be used.
	// Deprecated
	Ttl int32 `json:"ttl,omitempty"`
}

// NewAliCloudWriteAuthRoleRequestWithDefaults instantiates a new AliCloudWriteAuthRoleRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAliCloudWriteAuthRoleRequestWithDefaults() *AliCloudWriteAuthRoleRequest {
	var this AliCloudWriteAuthRoleRequest

	this.TokenType = "default-service"

	return &this
}
