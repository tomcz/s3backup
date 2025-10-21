package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"os"

	"github.com/tomcz/s3backup/v2/internal/client"
)

type shaHash struct{}

func NewHash() client.Hash {
	return &shaHash{}
}

func (h *shaHash) Calculate(filePath string) (string, error) {
	sum, err := h.shasum(filePath)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(sum), nil
}

func (h *shaHash) Verify(filePath, expectedChecksum string) error {
	expected, err := h.decode(expectedChecksum)
	if err != nil {
		return err
	}
	actual, err := h.shasum(filePath)
	if err != nil {
		return err
	}
	if bytes.Equal(actual, expected) {
		return nil
	}
	return errors.New("checksum: mismatch")
}

func (h *shaHash) shasum(filePath string) ([]byte, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	hash := sha256.New()
	if _, err = io.Copy(hash, file); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

func (h *shaHash) decode(expected string) ([]byte, error) {
	if expected == "" {
		return nil, errors.New("checksum: expected is blank")
	}
	return base64.StdEncoding.DecodeString(expected)
}
