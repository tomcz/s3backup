// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// PkiReadIssuerJsonResponse struct for PkiReadIssuerJsonResponse
type PkiReadIssuerJsonResponse struct {
	// CA Chain
	CaChain []string `json:"ca_chain,omitempty"`

	// Certificate
	Certificate string `json:"certificate,omitempty"`

	// Issuer Id
	IssuerId string `json:"issuer_id,omitempty"`

	// Issuer Name
	IssuerName string `json:"issuer_name,omitempty"`
}

// NewPkiReadIssuerJsonResponseWithDefaults instantiates a new PkiReadIssuerJsonResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewPkiReadIssuerJsonResponseWithDefaults() *PkiReadIssuerJsonResponse {
	var this PkiReadIssuerJsonResponse

	return &this
}
