package client

//go:generate mockgen --source=hash.go --destination=mocks/hash.go --package=mocks

type Hash interface {
	Calculate(filePath string) (string, error)
	Verify(filePath, expectedChecksum string) error
}
