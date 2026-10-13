package client

import "context"

//go:generate go run github.com/matryer/moq -out store_stub.go . Store:StoreStub

type Store interface {
	UploadFile(ctx context.Context, remotePath, localPath, checksum string, publicRead bool) error
	DownloadFile(ctx context.Context, remotePath, localPath string) (checksum string, err error)
}
