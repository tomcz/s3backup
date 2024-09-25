package client

//go:generate go run github.com/matryer/moq -out store_stub.go . Store:StoreStub

type Store interface {
	UploadFile(remotePath, localPath, checksum string) error
	DownloadFile(remotePath, localPath string) (checksum string, err error)
}
