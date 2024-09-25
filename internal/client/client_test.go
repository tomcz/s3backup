package client

import (
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func TestGetRemoteFileWithoutDecryption(t *testing.T) {
	hash := &HashStub{
		VerifyFunc: func(filePath string, expectedChecksum string) error {
			assert.Check(t, is.Equal("bar.txt", filePath))
			assert.Check(t, is.Equal("muahahaha", expectedChecksum))
			return nil
		},
	}
	store := &StoreStub{
		DownloadFileFunc: func(remotePath string, localPath string) (string, error) {
			assert.Check(t, is.Equal("s3://foo/bar.txt", remotePath))
			assert.Check(t, is.Equal("bar.txt", localPath))
			return "muahahaha", nil
		},
	}
	c := &Client{
		Hash:  hash,
		Store: store,
	}
	assert.NilError(t, c.GetRemoteFile("s3://foo/bar.txt", "bar.txt"))
}

func TestGetRemoteFileWithDecryption(t *testing.T) {
	hash := &HashStub{
		VerifyFunc: func(filePath string, expectedChecksum string) error {
			assert.Check(t, is.Equal("bar.txt.tmp", filePath))
			assert.Check(t, is.Equal("muahahaha", expectedChecksum))
			return nil
		},
	}
	store := &StoreStub{
		DownloadFileFunc: func(remotePath string, localPath string) (string, error) {
			assert.Check(t, is.Equal("s3://foo/bar.txt", remotePath))
			assert.Check(t, is.Equal("bar.txt.tmp", localPath))
			return "muahahaha", nil
		},
	}
	cipher := &CipherStub{
		DecryptFunc: func(cipherTextFile string, plainTextFile string) error {
			assert.Check(t, is.Equal("bar.txt.tmp", cipherTextFile))
			assert.Check(t, is.Equal("bar.txt", plainTextFile))
			return nil
		},
	}
	c := &Client{
		Hash:   hash,
		Store:  store,
		Cipher: cipher,
	}
	assert.NilError(t, c.GetRemoteFile("s3://foo/bar.txt", "bar.txt"))
}

func TestPutLocalFileWithoutEncryption(t *testing.T) {
	hash := &HashStub{
		CalculateFunc: func(filePath string) (string, error) {
			assert.Check(t, is.Equal("bar.txt", filePath))
			return "woahahaha", nil
		},
	}
	store := &StoreStub{
		UploadFileFunc: func(remotePath string, localPath string, checksum string) error {
			assert.Check(t, is.Equal("s3://foo/bar.txt", remotePath))
			assert.Check(t, is.Equal("bar.txt", localPath))
			assert.Check(t, is.Equal("woahahaha", checksum))
			return nil
		},
	}
	c := &Client{
		Hash:  hash,
		Store: store,
	}
	assert.NilError(t, c.PutLocalFile("s3://foo/bar.txt", "bar.txt"))
}

func TestPutLocalFileWithEncryption(t *testing.T) {
	hash := &HashStub{
		CalculateFunc: func(filePath string) (string, error) {
			assert.Check(t, is.Equal("bar.txt.tmp", filePath))
			return "woahahaha", nil
		},
	}
	store := &StoreStub{
		UploadFileFunc: func(remotePath string, localPath string, checksum string) error {
			assert.Check(t, is.Equal("s3://foo/bar.txt", remotePath))
			assert.Check(t, is.Equal("bar.txt.tmp", localPath))
			assert.Check(t, is.Equal("woahahaha", checksum))
			return nil
		},
	}
	cipher := &CipherStub{
		EncryptFunc: func(plainTextFile string, cipherTextFile string) error {
			assert.Check(t, is.Equal("bar.txt", plainTextFile))
			assert.Check(t, is.Equal("bar.txt.tmp", cipherTextFile))
			return nil
		},
	}
	c := &Client{
		Hash:   hash,
		Store:  store,
		Cipher: cipher,
	}
	assert.NilError(t, c.PutLocalFile("s3://foo/bar.txt", "bar.txt"))
}
