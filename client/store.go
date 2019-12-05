package client

type Store interface {
	UploadFile(remotePath, localPath, checksum string) error
	DownloadFile(remotePath, localPath string) (checksum string, err error)
}
