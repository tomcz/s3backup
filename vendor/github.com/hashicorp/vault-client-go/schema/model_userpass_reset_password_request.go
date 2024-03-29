// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// UserpassResetPasswordRequest struct for UserpassResetPasswordRequest
type UserpassResetPasswordRequest struct {
	// Password for this user.
	Password string `json:"password,omitempty"`
}

// NewUserpassResetPasswordRequestWithDefaults instantiates a new UserpassResetPasswordRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewUserpassResetPasswordRequestWithDefaults() *UserpassResetPasswordRequest {
	var this UserpassResetPasswordRequest

	return &this
}
