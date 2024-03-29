// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// AppRoleListRolesResponse struct for AppRoleListRolesResponse
type AppRoleListRolesResponse struct {
	Keys []string `json:"keys,omitempty"`
}

// NewAppRoleListRolesResponseWithDefaults instantiates a new AppRoleListRolesResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppRoleListRolesResponseWithDefaults() *AppRoleListRolesResponse {
	var this AppRoleListRolesResponse

	return &this
}
