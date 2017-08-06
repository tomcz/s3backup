package client

import (
	"testing"

	"s3backup/mocks"

	"github.com/stretchr/testify/assert"
)

func TestGetRemoteFileWithoutDecryption(t *testing.T) {
	hash := &mocks.Hash{}
	store := &mocks.Store{}

	c := &Client{
		Hash:  hash,
		Store: store,
	}

	store.On("DownloadFile", "s3://foo/bar.txt", "bar.txt").Return("muahahaha", nil)
	hash.On("Verify", "bar.txt", "muahahaha").Return(nil)

	assert.NoError(t, c.GetRemoteFile("s3://foo/bar.txt", "bar.txt"))

	hash.AssertExpectations(t)
	store.AssertExpectations(t)
}

func TestGetRemoteFileWithDecryption(t *testing.T) {
	hash := &mocks.Hash{}
	store := &mocks.Store{}
	cipher := &mocks.Cipher{}

	c := &Client{
		Hash:   hash,
		Store:  store,
		Cipher: cipher,
	}

	store.On("DownloadFile", "s3://foo/bar.txt", "bar.txt.tmp").Return("muahahaha", nil)
	hash.On("Verify", "bar.txt.tmp", "muahahaha").Return(nil)
	cipher.On("Decrypt", "bar.txt.tmp", "bar.txt").Return(nil)

	assert.NoError(t, c.GetRemoteFile("s3://foo/bar.txt", "bar.txt"))

	hash.AssertExpectations(t)
	store.AssertExpectations(t)
	cipher.AssertExpectations(t)
}

func TestPutLocalFileWithoutEncryption(t *testing.T) {
	hash := &mocks.Hash{}
	store := &mocks.Store{}

	c := &Client{
		Hash:  hash,
		Store: store,
	}

	hash.On("Calculate", "bar.txt").Return("woahahaha", nil)
	store.On("UploadFile", "s3://foo/bar.txt", "bar.txt", "woahahaha").Return(nil)

	assert.NoError(t, c.PutLocalFile("s3://foo/bar.txt", "bar.txt"))

	hash.AssertExpectations(t)
	store.AssertExpectations(t)
}

func TestPutLocalFileWithEncryption(t *testing.T) {
	hash := &mocks.Hash{}
	store := &mocks.Store{}
	cipher := &mocks.Cipher{}

	c := &Client{
		Hash:   hash,
		Store:  store,
		Cipher: cipher,
	}

	cipher.On("Encrypt", "bar.txt", "bar.txt.tmp").Return(nil)
	hash.On("Calculate", "bar.txt.tmp").Return("woahahaha", nil)
	store.On("UploadFile", "s3://foo/bar.txt", "bar.txt.tmp", "woahahaha").Return(nil)

	assert.NoError(t, c.PutLocalFile("s3://foo/bar.txt", "bar.txt"))

	hash.AssertExpectations(t)
	store.AssertExpectations(t)
	cipher.AssertExpectations(t)
}
