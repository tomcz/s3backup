// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// AwsConfigureIdentityWhitelistTidyOperationRequest struct for AwsConfigureIdentityWhitelistTidyOperationRequest
type AwsConfigureIdentityWhitelistTidyOperationRequest struct {
	// If set to 'true', disables the periodic tidying of the 'identity-accesslist/<instance_id>' entries.
	DisablePeriodicTidy bool `json:"disable_periodic_tidy,omitempty"`

	// The amount of extra time that must have passed beyond the identity's expiration, before it is removed from the backend storage.
	SafetyBuffer int32 `json:"safety_buffer,omitempty"`
}

// NewAwsConfigureIdentityWhitelistTidyOperationRequestWithDefaults instantiates a new AwsConfigureIdentityWhitelistTidyOperationRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAwsConfigureIdentityWhitelistTidyOperationRequestWithDefaults() *AwsConfigureIdentityWhitelistTidyOperationRequest {
	var this AwsConfigureIdentityWhitelistTidyOperationRequest

	this.DisablePeriodicTidy = false
	this.SafetyBuffer = 259200

	return &this
}
