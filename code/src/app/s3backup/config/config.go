package config

type Config struct {
	CipherKey   string `mapstructure:"cipher_key"`
	S3AccessKey string `mapstructure:"s3_access_key"`
	S3SecretKey string `mapstructure:"s3_secret_key"`
	S3Token     string `mapstructure:"s3_token"`
	S3Region    string `mapstructure:"s3_region"`
	S3Endpoint  string `mapstructure:"s3_endpoint"`
}
