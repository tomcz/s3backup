package crypto

import (
	"os"
	"testing"

	"gotest.tools/v3/assert"

	"github.com/tomcz/s3backup/v2/internal/utils"
)

func TestRoundTripAESEncryptDecrypt_GeneratedKey(t *testing.T) {
	key, err := GenerateAESKeyString()
	assert.NilError(t, err, "Cannot generate AES key")
	testRoundTrip(t, key)
}

func TestRoundTripAESEncryptDecrypt_ArbitraryKey(t *testing.T) {
	testRoundTrip(t, "password0")
}

func testRoundTrip(t *testing.T, key string) {
	expected, err := utils.Random(1024)
	assert.NilError(t, err, "Cannot create file contents")

	file, err := utils.CreateTempFile("aes", expected)
	assert.NilError(t, err, "Cannot create file to encrypt")
	defer os.Remove(file)

	cipher, err := NewAESCipher(key)
	assert.NilError(t, err, "Cannot create AES cipher")

	encryptedFile := file + ".enc"
	defer os.Remove(encryptedFile)

	decryptedFile := file + ".dec"
	defer os.Remove(decryptedFile)

	assert.NilError(t, cipher.Encrypt(file, encryptedFile), "Cannot encrypt file")
	assert.NilError(t, cipher.Decrypt(encryptedFile, decryptedFile), "Cannot decrypt file")

	actual, err := os.ReadFile(decryptedFile)
	assert.NilError(t, err, "Cannot read decrypted file")

	assert.DeepEqual(t, expected, actual)
}
