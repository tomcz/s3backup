package crypto

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tomcz/s3backup/utils"
)

func TestRoundTripAESEncryptDecrypt_GeneratedKey(t *testing.T) {
	key, err := GenerateAESKeyString()
	require.NoError(t, err, "Cannot generate AES key")
	testRoundTrip(t, key)
}

func TestRoundTripAESEncryptDecrypt_ArbitraryKey(t *testing.T) {
	testRoundTrip(t, "password0")
}

func testRoundTrip(t *testing.T, key string) {
	expected, err := utils.Random(1024)
	require.NoError(t, err, "Cannot create file contents")

	file, err := utils.CreateTempFile("aes", expected)
	require.NoError(t, err, "Cannot create file to encrypt")
	defer os.Remove(file)

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
