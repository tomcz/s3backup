package client

//go:generate mockgen --source=store.go --destination=mocks/store.go --package=mocks

type Store interface {
	IsRemote(path string) bool
	UploadFile(remotePath, localPath, checksum string) error
	DownloadFile(remotePath, localPath string) (checksum string, err error)
}
