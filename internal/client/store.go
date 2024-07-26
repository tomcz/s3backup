package client

//go:generate go run github.com/matryer/moq -out store_stub.go . Store:StoreStub

type Store interface {
	IsRemote(path string) bool
	UploadFile(remotePath, localPath, checksum string) error
	DownloadFile(remotePath, localPath string) (checksum string, err error)
}
