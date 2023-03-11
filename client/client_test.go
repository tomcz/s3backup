package client

import (
	"testing"

	"github.com/golang/mock/gomock"
	"gotest.tools/v3/assert"

	"github.com/tomcz/s3backup/client/mocks"
)

func TestGetRemoteFileWithoutDecryption(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	hash := mocks.NewMockHash(ctrl)
	store := mocks.NewMockStore(ctrl)

	c := &Client{
		Hash:  hash,
		Store: store,
	}

	store.EXPECT().IsRemote("bar.txt").Return(false).AnyTimes()
	store.EXPECT().IsRemote("s3://foo/bar.txt").Return(true).AnyTimes()
	store.EXPECT().DownloadFile("s3://foo/bar.txt", "bar.txt").Return("muahahaha", nil)
	hash.EXPECT().Verify("bar.txt", "muahahaha").Return(nil)

	assert.NilError(t, c.GetRemoteFile("bar.txt", "s3://foo/bar.txt"))
}

func TestGetRemoteFileWithDecryption(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	hash := mocks.NewMockHash(ctrl)
	store := mocks.NewMockStore(ctrl)
	cipher := mocks.NewMockCipher(ctrl)

	c := &Client{
		Hash:   hash,
		Store:  store,
		Cipher: cipher,
	}

	store.EXPECT().IsRemote("bar.txt").Return(false).AnyTimes()
	store.EXPECT().IsRemote("s3://foo/bar.txt").Return(true).AnyTimes()
	store.EXPECT().DownloadFile("s3://foo/bar.txt", "bar.txt.tmp").Return("muahahaha", nil)
	hash.EXPECT().Verify("bar.txt.tmp", "muahahaha").Return(nil)
	cipher.EXPECT().Decrypt("bar.txt.tmp", "bar.txt").Return(nil)

	assert.NilError(t, c.GetRemoteFile("s3://foo/bar.txt", "bar.txt"))
}

func TestPutLocalFileWithoutEncryption(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	hash := mocks.NewMockHash(ctrl)
	store := mocks.NewMockStore(ctrl)

	c := &Client{
		Hash:  hash,
		Store: store,
	}

	store.EXPECT().IsRemote("bar.txt").Return(false).AnyTimes()
	store.EXPECT().IsRemote("s3://foo/bar.txt").Return(true).AnyTimes()
	hash.EXPECT().Calculate("bar.txt").Return("woahahaha", nil)
	store.EXPECT().UploadFile("s3://foo/bar.txt", "bar.txt", "woahahaha").Return(nil)

	assert.NilError(t, c.PutLocalFile("bar.txt", "s3://foo/bar.txt"))
}

func TestPutLocalFileWithEncryption(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	hash := mocks.NewMockHash(ctrl)
	store := mocks.NewMockStore(ctrl)
	cipher := mocks.NewMockCipher(ctrl)

	c := &Client{
		Hash:   hash,
		Store:  store,
		Cipher: cipher,
	}

	store.EXPECT().IsRemote("bar.txt").Return(false).AnyTimes()
	store.EXPECT().IsRemote("s3://foo/bar.txt").Return(true).AnyTimes()
	cipher.EXPECT().Encrypt("bar.txt", "bar.txt.tmp").Return(nil)
	hash.EXPECT().Calculate("bar.txt.tmp").Return("woahahaha", nil)
	store.EXPECT().UploadFile("s3://foo/bar.txt", "bar.txt.tmp", "woahahaha").Return(nil)

	assert.NilError(t, c.PutLocalFile("s3://foo/bar.txt", "bar.txt"))
}
