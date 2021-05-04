package client

type Hash interface {
	Calculate(filePath string) (string, error)
	Verify(filePath, expectedChecksum string) error
}

//go:generate mockgen --source=hash.go --destination=mocks/hash.go --package=mocks
