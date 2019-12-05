package client

type Hash interface {
	Calculate(filePath string) (string, error)
	Verify(filePath, expectedChecksum string) error
}
