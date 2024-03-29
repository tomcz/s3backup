// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// PluginsCatalogListPluginsResponse struct for PluginsCatalogListPluginsResponse
type PluginsCatalogListPluginsResponse struct {
	Detailed map[string]interface{} `json:"detailed,omitempty"`
}

// NewPluginsCatalogListPluginsResponseWithDefaults instantiates a new PluginsCatalogListPluginsResponse object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewPluginsCatalogListPluginsResponseWithDefaults() *PluginsCatalogListPluginsResponse {
	var this PluginsCatalogListPluginsResponse

	return &this
}
