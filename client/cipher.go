package client

type Cipher interface {
	Encrypt(plainTextFile, cipherTextFile string) error
	Decrypt(cipherTextFile, plainTextFile string) error
}
