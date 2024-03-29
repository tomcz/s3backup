// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// InternalCountTokensResponse struct for InternalCountTokensResponse
type InternalCountTokensResponse struct {
	Counters map[string]interface{} `json:"counters,omitempty"`
}

// NewInternalCountTokensResponseWithDefaults instantiates a new InternalCountTokensResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewInternalCountTokensResponseWithDefaults() *InternalCountTokensResponse {
	var this InternalCountTokensResponse

	return &this
}
