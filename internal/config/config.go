package config

type Config struct {
	CipherKey   string `mapstructure:"cipher_key"`    // Optional but highly recommended
	ForceV1     bool   `mapstructure:"old_password"`  // Maintain password compatiblilty with older s3backup releases
	PublicKey   string `mapstructure:"public_key"`    // Optional but highly recommended
	PrivateKey  string `mapstructure:"private_key"`   // Optional but highly recommended
	S3AccessKey string `mapstructure:"s3_access_key"` // Mandatory, Access Key ID
	S3SecretKey string `mapstructure:"s3_secret_key"` // Mandatory, Secret Access Key
	S3Token     string `mapstructure:"s3_token"`      // Optional, depends on your AWS configuration
	S3Region    string `mapstructure:"s3_region"`     // Optional, will use AWS defaults if not present
	S3Endpoint  string `mapstructure:"s3_endpoint"`   // Optional, will use AWS defaults if not present
}
