package crypto

import (
	"os"
	"testing"

	assert "github.com/stretchr/testify/require"

	"github.com/tomcz/s3backup/internal/utils"
)

func TestRoundTripRSAEncryptDecrypt(t *testing.T) {
	expected, err := utils.Random(1024)
	assert.NoError(t, err, "Cannot create file contents")

	file, err := utils.CreateTempFile("rsa", expected)
	assert.NoError(t, err, "Cannot create file to encrypt")
	defer os.Remove(file)

	privFile, err := utils.CreateTempFile("privkey", []byte{})
	assert.NoError(t, err, "Cannot create private key file")
	defer os.Remove(privFile)

	pubFile, err := utils.CreateTempFile("pubkey", []byte{})
	assert.NoError(t, err, "Cannot create public key file")
	defer os.Remove(pubFile)

	assert.NoError(t, GenerateRSAKeyPair(privFile, pubFile), "Cannot generate RSA key pair")

	privCipher, err := NewRSACipher(privFile)
	assert.NoError(t, err, "Cannot create RSA private cipher")

	pubCipher, err := NewRSACipher(pubFile)
	assert.NoError(t, err, "Cannot create RSA public cipher")

	encryptedFile := file + ".enc"
	defer os.Remove(encryptedFile)

	decryptedFile := file + ".dec"
	defer os.Remove(decryptedFile)

	assert.NoError(t, pubCipher.Encrypt(file, encryptedFile), "Cannot encrypt file")
	assert.NoError(t, privCipher.Decrypt(encryptedFile, decryptedFile), "Cannot decrypt file")

	actual, err := os.ReadFile(decryptedFile)
	assert.NoError(t, err, "Cannot read decrypted file")

	assert.Equal(t, expected, actual)
}
