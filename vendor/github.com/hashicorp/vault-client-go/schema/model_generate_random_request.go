// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// GenerateRandomRequest struct for GenerateRandomRequest
type GenerateRandomRequest struct {
	// The number of bytes to generate (POST body parameter). Defaults to 32 (256 bits).
	Bytes int32 `json:"bytes,omitempty"`

	// Encoding format to use. Can be \"hex\" or \"base64\". Defaults to \"base64\".
	Format string `json:"format,omitempty"`

	// Which system to source random data from, ether \"platform\", \"seal\", or \"all\".
	Source string `json:"source,omitempty"`

	// The number of bytes to generate (POST URL parameter)
	Urlbytes string `json:"urlbytes,omitempty"`
}

// NewGenerateRandomRequestWithDefaults instantiates a new GenerateRandomRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewGenerateRandomRequestWithDefaults() *GenerateRandomRequest {
	var this GenerateRandomRequest

	this.Bytes = 32
	this.Format = "base64"
	this.Source = "platform"

	return &this
}
