package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetRemoteFileWithoutDecryption(t *testing.T) {
	hash := &HashStub{
		VerifyFunc: func(filePath string, expectedChecksum string) error {
			assert.Equal(t, "bar.txt", filePath)
			assert.Equal(t, "muahahaha", expectedChecksum)
			return nil
		},
	}
	store := &StoreStub{
		IsRemoteFunc: func(path string) bool {
			switch path {
			case "bar.txt":
				return false
			case "s3://foo/bar.txt":
				return true
			default:
				t.Errorf("unexpected path: %q", path)
				return false
			}
		},
		DownloadFileFunc: func(remotePath string, localPath string) (string, error) {
			assert.Equal(t, "s3://foo/bar.txt", remotePath)
			assert.Equal(t, "bar.txt", localPath)
			return "muahahaha", nil
		},
	}
	c := &Client{
		Hash:  hash,
		Store: store,
	}
	assert.NoError(t, c.GetRemoteFile("bar.txt", "s3://foo/bar.txt"))
}

func TestGetRemoteFileWithDecryption(t *testing.T) {
	hash := &HashStub{
		VerifyFunc: func(filePath string, expectedChecksum string) error {
			assert.Equal(t, "bar.txt.tmp", filePath)
			assert.Equal(t, "muahahaha", expectedChecksum)
			return nil
		},
	}
	store := &StoreStub{
		IsRemoteFunc: func(path string) bool {
			switch path {
			case "bar.txt":
				return false
			case "s3://foo/bar.txt":
				return true
			default:
				t.Errorf("unexpected path: %q", path)
				return false
			}
		},
		DownloadFileFunc: func(remotePath string, localPath string) (string, error) {
			assert.Equal(t, "s3://foo/bar.txt", remotePath)
			assert.Equal(t, "bar.txt.tmp", localPath)
			return "muahahaha", nil
		},
	}
	cipher := &CipherStub{
		DecryptFunc: func(cipherTextFile string, plainTextFile string) error {
			assert.Equal(t, "bar.txt.tmp", cipherTextFile)
			assert.Equal(t, "bar.txt", plainTextFile)
			return nil
		},
	}
	c := &Client{
		Hash:   hash,
		Store:  store,
		Cipher: cipher,
	}
	assert.NoError(t, c.GetRemoteFile("s3://foo/bar.txt", "bar.txt"))
}

func TestPutLocalFileWithoutEncryption(t *testing.T) {
	hash := &HashStub{
		CalculateFunc: func(filePath string) (string, error) {
			assert.Equal(t, "bar.txt", filePath)
			return "woahahaha", nil
		},
	}
	store := &StoreStub{
		IsRemoteFunc: func(path string) bool {
			switch path {
			case "bar.txt":
				return false
			case "s3://foo/bar.txt":
				return true
			default:
				t.Errorf("unexpected path: %q", path)
				return false
			}
		},
		UploadFileFunc: func(remotePath string, localPath string, checksum string) error {
			assert.Equal(t, "s3://foo/bar.txt", remotePath)
			assert.Equal(t, "bar.txt", localPath)
			assert.Equal(t, "woahahaha", checksum)
			return nil
		},
	}
	c := &Client{
		Hash:  hash,
		Store: store,
	}
	assert.NoError(t, c.PutLocalFile("bar.txt", "s3://foo/bar.txt"))
}

func TestPutLocalFileWithEncryption(t *testing.T) {
	hash := &HashStub{
		CalculateFunc: func(filePath string) (string, error) {
			assert.Equal(t, "bar.txt.tmp", filePath)
			return "woahahaha", nil
		},
	}
	store := &StoreStub{
		IsRemoteFunc: func(path string) bool {
			switch path {
			case "bar.txt":
				return false
			case "s3://foo/bar.txt":
				return true
			default:
				t.Errorf("unexpected path: %q", path)
				return false
			}
		},
		UploadFileFunc: func(remotePath string, localPath string, checksum string) error {
			assert.Equal(t, "s3://foo/bar.txt", remotePath)
			assert.Equal(t, "bar.txt.tmp", localPath)
			assert.Equal(t, "woahahaha", checksum)
			return nil
		},
	}
	cipher := &CipherStub{
		EncryptFunc: func(plainTextFile string, cipherTextFile string) error {
			assert.Equal(t, "bar.txt", plainTextFile)
			assert.Equal(t, "bar.txt.tmp", cipherTextFile)
			return nil
		},
	}
	c := &Client{
		Hash:   hash,
		Store:  store,
		Cipher: cipher,
	}
	assert.NoError(t, c.PutLocalFile("s3://foo/bar.txt", "bar.txt"))
}
