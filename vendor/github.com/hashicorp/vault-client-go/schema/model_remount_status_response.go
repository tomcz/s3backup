// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// RemountStatusResponse struct for RemountStatusResponse
type RemountStatusResponse struct {
	MigrationId string `json:"migration_id,omitempty"`

	MigrationInfo map[string]interface{} `json:"migration_info,omitempty"`
}

// NewRemountStatusResponseWithDefaults instantiates a new RemountStatusResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewRemountStatusResponseWithDefaults() *RemountStatusResponse {
	var this RemountStatusResponse

	return &this
}
