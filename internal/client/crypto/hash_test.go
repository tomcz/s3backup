package crypto

import (
	"os"
	"path"
	"testing"

	"gotest.tools/v3/assert"
)

func TestVerifyHashOnSameFile(t *testing.T) {
	buf := randomBytes(1024)

	file := path.Join(t.TempDir(), "data")
	err := os.WriteFile(file, buf, 0600)
	assert.NilError(t, err, "Cannot create file to hash")

	hash := NewHash()

	checksum, err := hash.Calculate(file)
	assert.NilError(t, err, "Cannot create checksum")

	err = hash.Verify(file, checksum)
	assert.NilError(t, err, "Unexpected mismatch")
}

func TestVerifyHashOnDifferentFiles(t *testing.T) {
	buf1 := randomBytes(1024)
	buf2 := randomBytes(1024)

	tempDir := t.TempDir()
	file1 := path.Join(tempDir, "buf1")
	file2 := path.Join(tempDir, "buf2")

	err := os.WriteFile(file1, buf1, 0600)
	assert.NilError(t, err, "Cannot create file to hash")
	err = os.WriteFile(file2, buf2, 0600)
	assert.NilError(t, err, "Cannot create file to hash")

	hash := NewHash()

	checksum, err := hash.Calculate(file1)
	assert.NilError(t, err, "Cannot create checksum")

	err = hash.Verify(file2, checksum)
	assert.Error(t, err, "checksum: mismatch")
}

func TestVerifyHashBlank(t *testing.T) {
	hash := NewHash()
	err := hash.Verify("wibble", "")
	assert.Error(t, err, "checksum: expected is blank")
}
