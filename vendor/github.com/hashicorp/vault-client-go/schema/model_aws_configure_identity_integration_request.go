// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0
//
// Code generated with OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package schema

// AwsConfigureIdentityIntegrationRequest struct for AwsConfigureIdentityIntegrationRequest
type AwsConfigureIdentityIntegrationRequest struct {
	// Configure how the AWS auth method generates entity alias when using EC2 auth. Valid values are \"role_id\", \"instance_id\", and \"image_id\". Defaults to \"role_id\".
	Ec2Alias string `json:"ec2_alias,omitempty"`

	// The metadata to include on the aliases and audit logs generated by this plugin. When set to 'default', includes: account_id, auth_type. These fields are available to add: ami_id, instance_id, region. Not editing this field means the 'default' fields are included. Explicitly setting this field to empty overrides the 'default' and means no metadata will be included. If not using 'default', explicit fields must be sent like: 'field1,field2'.
	Ec2Metadata []string `json:"ec2_metadata,omitempty"`

	// Configure how the AWS auth method generates entity aliases when using IAM auth. Valid values are \"role_id\", \"unique_id\", and \"full_arn\". Defaults to \"role_id\".
	IamAlias string `json:"iam_alias,omitempty"`

	// The metadata to include on the aliases and audit logs generated by this plugin. When set to 'default', includes: account_id, auth_type. These fields are available to add: canonical_arn, client_arn, client_user_id, inferred_aws_region, inferred_entity_id, inferred_entity_type. Not editing this field means the 'default' fields are included. Explicitly setting this field to empty overrides the 'default' and means no metadata will be included. If not using 'default', explicit fields must be sent like: 'field1,field2'.
	IamMetadata []string `json:"iam_metadata,omitempty"`
}

// NewAwsConfigureIdentityIntegrationRequestWithDefaults instantiates a new AwsConfigureIdentityIntegrationRequest object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewAwsConfigureIdentityIntegrationRequestWithDefaults() *AwsConfigureIdentityIntegrationRequest {
	var this AwsConfigureIdentityIntegrationRequest

	this.Ec2Alias = "instance_id"
	this.IamAlias = "unique_id"

	return &this
}
