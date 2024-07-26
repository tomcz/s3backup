package crypto

import (
	"os"
	"testing"

	assert "github.com/stretchr/testify/require"

	"github.com/tomcz/s3backup/internal/utils"
)

func TestVerifyHashOnSameFile(t *testing.T) {
	buf, err := utils.Random(1024)
	assert.NoError(t, err, "Cannot create file contents")

	file, err := utils.CreateTempFile("hash", buf)
	assert.NoError(t, err, "Cannot create file to hash")
	defer os.Remove(file)

	hash := NewHash()

	checksum, err := hash.Calculate(file)
	assert.NoError(t, err, "Cannot create checksum")

	assert.NoError(t, hash.Verify(file, checksum), "Unexpected mismatch")
}

func TestVerifyHashOnDifferentFiles(t *testing.T) {
	buf1, err := utils.Random(1024)
	assert.NoError(t, err, "Cannot create file contents")

	file1, err := utils.CreateTempFile("hash", buf1)
	assert.NoError(t, err, "Cannot create file to hash")
	defer os.Remove(file1)

	buf2, err := utils.Random(1024)
	assert.NoError(t, err, "Cannot create file contents")

	file2, err := utils.CreateTempFile("hash", buf2)
	assert.NoError(t, err, "Cannot create file to hash")
	defer os.Remove(file2)

	hash := NewHash()

	checksum, err := hash.Calculate(file1)
	assert.NoError(t, err, "Cannot create checksum")

	assert.ErrorContains(t, hash.Verify(file2, checksum), "checksum mismatch")
}

func TestVerifyHashBlank(t *testing.T) {
	hash := NewHash()
	err := hash.Verify("wibble", "")
	assert.Error(t, err, "checksum error: expected is blank")
}
