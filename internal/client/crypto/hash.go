package crypto

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/tomcz/s3backup/internal/client"
)

type shaHash struct{}

func NewHash() client.Hash {
	return &shaHash{}
}

func (h *shaHash) Calculate(filePath string) (string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString(hash.Sum(nil)), nil
}

func (h *shaHash) Verify(filePath, expectedChecksum string) error {
	if expectedChecksum == "" {
		return fmt.Errorf("checksum error: expected is blank")
	}
	actualChecksum, err := h.Calculate(filePath)
	if err != nil {
		return err
	}
	if expectedChecksum != actualChecksum {
		return fmt.Errorf("checksum mismatch: expected %v, actual %v", expectedChecksum, actualChecksum)
	}
	return nil
}
