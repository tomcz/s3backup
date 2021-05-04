package client

type Cipher interface {
	Encrypt(plainTextFile, cipherTextFile string) error
	Decrypt(cipherTextFile, plainTextFile string) error
}

//go:generate mockgen --source=cipher.go --destination=mocks/cipher.go --package=mocks
