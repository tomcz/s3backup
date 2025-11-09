package crypto

import (
	"crypto/rand"
	"os"
	"path"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
)

func TestRoundTripRSAEncryptDecrypt(t *testing.T) {
	var builder strings.Builder
	for range 100 {
		builder.WriteString(rand.Text())
	}
	expected := builder.String()

	tmpDir := t.TempDir()
	file := path.Join(tmpDir, "data")
	privFile := path.Join(tmpDir, "priv")
	pubFile := path.Join(tmpDir, "pub")

	err := os.WriteFile(file, []byte(expected), 0600)
	assert.NilError(t, err, "Failed to write data file")

	assert.NilError(t, GenerateRSAKeyPair(privFile, pubFile), "Cannot generate RSA key pair")

	privCipher, err := NewRSACipher(privFile)
	assert.NilError(t, err, "Cannot create RSA private cipher")

	pubCipher, err := NewRSACipher(pubFile)
	assert.NilError(t, err, "Cannot create RSA public cipher")

	encryptedFile := file + ".enc"
	decryptedFile := file + ".dec"

	assert.NilError(t, pubCipher.Encrypt(file, encryptedFile), "Cannot encrypt file")
	assert.NilError(t, privCipher.Decrypt(encryptedFile, decryptedFile), "Cannot decrypt file")

	actual, err := os.ReadFile(decryptedFile)
	assert.NilError(t, err, "Cannot read decrypted file")
	assert.Equal(t, expected, string(actual))
}
