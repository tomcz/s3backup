package crypto

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"github.com/tomcz/s3backup/v2/internal/client"
)

type shaHash struct {
	hexEncode bool
}

func NewHash(hexEncode bool) client.Hash {
	return &shaHash{hexEncode}
}

func (h *shaHash) Calculate(filePath string) (string, error) {
	sum, err := h.shasum(filePath)
	if err != nil {
		return "", err
	}
	if h.hexEncode {
		return hex.EncodeToString(sum), nil
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
	if subtle.ConstantTimeCompare(expected, actual) == 1 {
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
	if h.hexEncode {
		return hex.DecodeString(expected)
	}
	return base64.StdEncoding.DecodeString(expected)
}
