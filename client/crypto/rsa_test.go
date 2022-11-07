package crypto

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tomcz/s3backup/utils"
)

func TestRoundTripRSAEncryptDecrypt(t *testing.T) {
	expected, err := utils.Random(1024)
	require.NoError(t, err, "Cannot create file contents")

	file, err := utils.CreateTempFile("rsa", expected)
	require.NoError(t, err, "Cannot create file to encrypt")
	defer os.Remove(file)

	privFile, err := utils.CreateTempFile("privkey", []byte{})
	require.NoError(t, err, "Cannot create private key file")
	defer os.Remove(privFile)

	pubFile, err := utils.CreateTempFile("pubkey", []byte{})
	require.NoError(t, err, "Cannot create public key file")
	defer os.Remove(pubFile)

	require.NoError(t, GenerateRSAKeyPair(privFile, pubFile), "Cannot generate RSA key pair")

	privCipher, err := NewRSACipher(privFile)
	require.NoError(t, err, "Cannot create RSA private cipher")

	pubCipher, err := NewRSACipher(pubFile)
	require.NoError(t, err, "Cannot create RSA public cipher")

	encryptedFile := file + ".enc"
	defer os.Remove(encryptedFile)

	decryptedFile := file + ".dec"
	defer os.Remove(decryptedFile)

	require.NoError(t, pubCipher.Encrypt(file, encryptedFile), "Cannot encrypt file")
	require.NoError(t, privCipher.Decrypt(encryptedFile, decryptedFile), "Cannot decrypt file")

	actual, err := os.ReadFile(decryptedFile)
	require.NoError(t, err, "Cannot read decrypted file")

	assert.Equal(t, expected, actual, "File contents are different")
}
