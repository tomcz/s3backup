// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// RadiusConfigureRequest struct for RadiusConfigureRequest
type RadiusConfigureRequest struct {
	// Number of seconds before connect times out (default: 10)
	DialTimeout int32 `json:"dial_timeout,omitempty"`

	// RADIUS server host
	Host string `json:"host,omitempty"`

	// RADIUS NAS Identifier field (optional)
	NasIdentifier string `json:"nas_identifier,omitempty"`

	// RADIUS NAS port field (default: 10)
	NasPort int32 `json:"nas_port,omitempty"`

	// RADIUS server port (default: 1812)
	Port int32 `json:"port,omitempty"`

	// Number of seconds before response times out (default: 10)
	ReadTimeout int32 `json:"read_timeout,omitempty"`

	// Secret shared with the RADIUS server
	Secret string `json:"secret,omitempty"`

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

	// Comma-separated list of policies. This will apply to all tokens generated by this auth method, in addition to any configured for specific users.
	TokenPolicies []string `json:"token_policies,omitempty"`

	// The initial ttl of the token to generate
	TokenTtl int32 `json:"token_ttl,omitempty"`

	// The type of token to generate, service or batch
	TokenType string `json:"token_type,omitempty"`

	// Comma-separated list of policies to grant upon successful RADIUS authentication of an unregistered user (default: empty)
	UnregisteredUserPolicies string `json:"unregistered_user_policies,omitempty"`
}

// NewRadiusConfigureRequestWithDefaults instantiates a new RadiusConfigureRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewRadiusConfigureRequestWithDefaults() *RadiusConfigureRequest {
	var this RadiusConfigureRequest

	this.DialTimeout = 10
	this.NasIdentifier = ""
	this.NasPort = 10
	this.Port = 1812
	this.ReadTimeout = 10
	this.TokenType = "default-service"
	this.UnregisteredUserPolicies = ""

	return &this
}
