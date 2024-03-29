// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// AppRoleWriteBoundCidrListRequest struct for AppRoleWriteBoundCidrListRequest
type AppRoleWriteBoundCidrListRequest struct {
	// Deprecated: Please use \"secret_id_bound_cidrs\" instead. Comma separated string or list of CIDR blocks. If set, specifies the blocks of IP addresses which can perform the login operation.
	BoundCidrList []string `json:"bound_cidr_list,omitempty"`
}

// NewAppRoleWriteBoundCidrListRequestWithDefaults instantiates a new AppRoleWriteBoundCidrListRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAppRoleWriteBoundCidrListRequestWithDefaults() *AppRoleWriteBoundCidrListRequest {
	var this AppRoleWriteBoundCidrListRequest

	return &this
}
