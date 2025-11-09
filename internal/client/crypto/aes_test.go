package crypto

import (
	"crypto/rand"
	"os"
	"path"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
)

func TestRoundTripAESEncryptDecrypt_GeneratedKey(t *testing.T) {
	testRoundTrip(t, GenerateAESKeyString(), false, symV1Header)
}

func TestRoundTripAESEncryptDecrypt_Password_v1(t *testing.T) {
	testRoundTrip(t, "password0", true, symV1Header)
}

func TestRoundTripAESEncryptDecrypt_Password_v2(t *testing.T) {
	testRoundTrip(t, "password0", false, symV2Header)
}

func testRoundTrip(t *testing.T, key string, forceV1 bool, expectedHeader string) {
	var builder strings.Builder
	for range 100 {
		builder.WriteString(rand.Text())
	}
	expected := builder.String()

	file := path.Join(t.TempDir(), "data")
	err := os.WriteFile(file, []byte(expected), 0600)
	assert.NilError(t, err, "Cannot create file to encrypt")

	cipher, err := NewAESCipher(key, forceV1)
	assert.NilError(t, err, "Cannot create AES cipher")

	encryptedFile := file + ".enc"
	decryptedFile := file + ".dec"

	assert.NilError(t, cipher.Encrypt(file, encryptedFile), "Cannot encrypt file")

	encrypted, err := os.ReadFile(encryptedFile)
	assert.NilError(t, err, "Cannot read encrypted file")
	actualHeader := encrypted[:len(expectedHeader)]
	assert.Equal(t, expectedHeader, string(actualHeader))

	assert.NilError(t, cipher.Decrypt(encryptedFile, decryptedFile), "Cannot decrypt file")

	actual, err := os.ReadFile(decryptedFile)
	assert.NilError(t, err, "Cannot read decrypted file")
	assert.Equal(t, expected, string(actual))
}
