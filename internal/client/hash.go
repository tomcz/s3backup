package client

//go:generate go tool moq -out hash_stub.go . Hash:HashStub

type Hash interface {
	Calculate(filePath string) (string, error)
	Verify(filePath, expectedChecksum string) error
}
