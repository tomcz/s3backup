package crypto

const asymKeyVersion = "BAKv1"
const symKeyVersion = "BSKv1"

type Cipher interface {
	Encrypt(plainTextFile, cipherTextFile string) error
	Decrypt(cipherTextFile, plainTextFile string) error
}
