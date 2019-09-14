package crypto

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRoundTripAESEncryptDecrypt(t *testing.T) {
	expected, err := Random(1024)
	require.NoError(t, err, "Cannot create file contents")

	file, err := CreateTempFile("aes", expected)
	require.NoError(t, err, "Cannot create file to encrypt")
	defer os.Remove(file)

	key, err := GenerateAESKeyString()
	require.NoError(t, err, "Cannot generate AES key")

	cipher, err := NewAESCipher(key)
	require.NoError(t, err, "Cannot create AES cipher")

	encryptedFile := file + ".enc"
	defer os.Remove(encryptedFile)

	decryptedFile := file + ".dec"
	defer os.Remove(decryptedFile)

	require.NoError(t, cipher.Encrypt(file, encryptedFile), "Cannot encrypt file")
	require.NoError(t, cipher.Decrypt(encryptedFile, decryptedFile), "Cannot decrypt file")

	actual, err := ioutil.ReadFile(decryptedFile)
	require.NoError(t, err, "Cannot read decrypted file")

	assert.Equal(t, expected, actual, "File contents are different")
}
