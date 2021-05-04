package client

type Store interface {
	UploadFile(remotePath, localPath, checksum string) error
	DownloadFile(remotePath, localPath string, readChecksum bool) (checksum string, err error)
}

//go:generate mockgen --source=store.go --destination=mocks/store.go --package=mocks
