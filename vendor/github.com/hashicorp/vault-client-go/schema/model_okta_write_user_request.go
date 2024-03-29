// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// OktaWriteUserRequest struct for OktaWriteUserRequest
type OktaWriteUserRequest struct {
	// List of groups associated with the user.
	Groups []string `json:"groups,omitempty"`

	// List of policies associated with the user.
	Policies []string `json:"policies,omitempty"`
}

// NewOktaWriteUserRequestWithDefaults instantiates a new OktaWriteUserRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewOktaWriteUserRequestWithDefaults() *OktaWriteUserRequest {
	var this OktaWriteUserRequest

	return &this
}
