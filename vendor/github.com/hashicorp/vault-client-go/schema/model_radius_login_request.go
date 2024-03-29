// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// RadiusLoginRequest struct for RadiusLoginRequest
type RadiusLoginRequest struct {
	// Password for this user.
	Password string `json:"password,omitempty"`

	// Username to be used for login. (URL parameter)
	Urlusername string `json:"urlusername,omitempty"`

	// Username to be used for login. (POST request body)
	Username string `json:"username,omitempty"`
}

// NewRadiusLoginRequestWithDefaults instantiates a new RadiusLoginRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewRadiusLoginRequestWithDefaults() *RadiusLoginRequest {
	var this RadiusLoginRequest

	return &this
}
