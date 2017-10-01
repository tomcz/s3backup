package store

type Store interface {
	UploadFile(remotePath, localPath, checksum string) error
	DownloadFile(remotePath, localPath string) (string, error)
}
