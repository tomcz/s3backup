package crypto

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/tomcz/s3backup/utils"
)

func TestVerifyHashOnSameFile(t *testing.T) {
	buf, err := utils.Random(1024)
	require.NoError(t, err, "Cannot create file contents")

	file, err := utils.CreateTempFile("hash", buf)
	require.NoError(t, err, "Cannot create file to hash")
	defer os.Remove(file)

	hash := NewHash()

	checksum, err := hash.Calculate(file)
	require.NoError(t, err, "Cannot create checksum")

	assert.NoError(t, hash.Verify(file, checksum), "Unexpected mismatch")
}

func TestVerifyHashOnDifferentFiles(t *testing.T) {
	buf1, err := utils.Random(1024)
	require.NoError(t, err, "Cannot create file contents")

	file1, err := utils.CreateTempFile("hash", buf1)
	require.NoError(t, err, "Cannot create file to hash")
	defer os.Remove(file1)

	buf2, err := utils.Random(1024)
	require.NoError(t, err, "Cannot create file contents")

	file2, err := utils.CreateTempFile("hash", buf2)
	require.NoError(t, err, "Cannot create file to hash")
	defer os.Remove(file2)

	hash := NewHash()

	checksum, err := hash.Calculate(file1)
	require.NoError(t, err, "Cannot create checksum")

	assert.Error(t, hash.Verify(file2, checksum), "Unexpected match")
}

func TestVerifyHashBlank(t *testing.T) {
	hash := NewHash()
	err := hash.Verify("wibble", "")
	assert.EqualError(t, err, "checksum error: expected is blank")
}
