package client

//go:generate go tool moq -out ciper_stub.go . Cipher:CipherStub

type Cipher interface {
	Encrypt(plainTextFile, cipherTextFile string) error
	Decrypt(cipherTextFile, plainTextFile string) error
}
