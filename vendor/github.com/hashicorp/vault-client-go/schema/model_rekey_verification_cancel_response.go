// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// RekeyVerificationCancelResponse struct for RekeyVerificationCancelResponse
type RekeyVerificationCancelResponse struct {
	N int32 `json:"n,omitempty"`

	Nounce string `json:"nounce,omitempty"`

	Progress int32 `json:"progress,omitempty"`

	Started string `json:"started,omitempty"`

	T int32 `json:"t,omitempty"`
}

// NewRekeyVerificationCancelResponseWithDefaults instantiates a new RekeyVerificationCancelResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewRekeyVerificationCancelResponseWithDefaults() *RekeyVerificationCancelResponse {
	var this RekeyVerificationCancelResponse

	return &this
}
