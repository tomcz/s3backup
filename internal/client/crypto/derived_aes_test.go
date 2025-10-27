package crypto

import (
	"os"
	"path"
	"testing"

	"gotest.tools/v3/assert"
)

func TestDerivedAESCipher_RoundTrip(t *testing.T) {
	expected := randomBytes(1024)

	file := path.Join(t.TempDir(), "data")
	err := os.WriteFile(file, expected, 0600)
	assert.NilError(t, err, "Cannot create file to encrypt")

	cipher := &derivedAesCipher{
		password:   []byte("this is a secret"),
		saltSize:   8,
		scryptCost: 1 << 14,
	}

	encryptedFile := file + ".enc"
	decryptedFile := file + ".dec"

	assert.NilError(t, cipher.Encrypt(file, encryptedFile), "Cannot encrypt file")
	assert.NilError(t, cipher.Decrypt(encryptedFile, decryptedFile), "Cannot decrypt file")

	actual, err := os.ReadFile(decryptedFile)
	assert.NilError(t, err, "Cannot read decrypted file")

	assert.DeepEqual(t, expected, actual)
}
