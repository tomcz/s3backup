// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// AppRoleWriteBindSecretIdRequest struct for AppRoleWriteBindSecretIdRequest
type AppRoleWriteBindSecretIdRequest struct {
	// Impose secret_id to be presented when logging in using this role.
	BindSecretId bool `json:"bind_secret_id,omitempty"`
}

// NewAppRoleWriteBindSecretIdRequestWithDefaults instantiates a new AppRoleWriteBindSecretIdRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppRoleWriteBindSecretIdRequestWithDefaults() *AppRoleWriteBindSecretIdRequest {
	var this AppRoleWriteBindSecretIdRequest

	this.BindSecretId = true

	return &this
}
