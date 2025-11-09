package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"golang.org/x/crypto/scrypt"

	"github.com/tomcz/s3backup/v2/internal/client"
)

const (
	v2SaltSize = 16
	v2KeyCost  = 1 << 20
)

type aesCipher struct {
	key   []byte
	useV1 bool
}

func NewAESCipher(secretKey string, forceV1 bool) (client.Cipher, error) {
	secretKey = strings.TrimSpace(secretKey)
	if secretKey == "" {
		return nil, fmt.Errorf("cannot use a blank secret key")
	}
	key, err := base64.StdEncoding.DecodeString(secretKey)
	if err == nil && len(key) == 32 {
		return &aesCipher{
			key:   key,
			useV1: true,
		}, nil
	}
	if forceV1 {
		sum := sha256.Sum256([]byte(secretKey))
		return &aesCipher{
			key:   sum[:],
			useV1: true,
		}, nil
	}
	return &aesCipher{
		key:   []byte(secretKey),
		useV1: false,
	}, nil
}

func (c *aesCipher) Encrypt(plainTextFile, cipherTextFile string) error {
	block, preamble, err := c.encryptCipher()
	if err != nil {
		return err
	}

	iv := randomBytes(block.BlockSize())

	outFile, err := os.Create(cipherTextFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	if _, err = outFile.Write(preamble); err != nil {
		return err
	}
	if _, err = outFile.Write(iv); err != nil {
		return err
	}

	inFile, err := os.Open(plainTextFile)
	if err != nil {
		return err
	}
	defer inFile.Close()

	stream := cipher.NewCTR(block, iv)
	writer := &cipher.StreamWriter{S: stream, W: outFile}
	_, err = io.Copy(writer, inFile)
	return err
}

func (c *aesCipher) Decrypt(cipherTextFile, plainTextFile string) error {
	inFile, err := os.Open(cipherTextFile)
	if err != nil {
		return err
	}
	defer inFile.Close()

	block, err := c.decryptCipher(inFile)
	if err != nil {
		return err
	}

	iv := make([]byte, block.BlockSize())
	if _, err = inFile.Read(iv); err != nil {
		return err
	}

	outFile, err := os.Create(plainTextFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	stream := cipher.NewCTR(block, iv)
	reader := &cipher.StreamReader{S: stream, R: inFile}
	_, err = io.Copy(outFile, reader)
	return err
}

func (c *aesCipher) encryptCipher() (cipher.Block, []byte, error) {
	if c.useV1 {
		preamble := slices.Clone([]byte(symV1Header))
		block, err := aes.NewCipher(c.key)
		return block, preamble, err
	}
	salt := randomBytes(v2SaltSize)
	key, err := c.v2Key(salt)
	if err != nil {
		return nil, nil, err
	}
	preamble := slices.Concat([]byte(symV2Header), salt)
	block, err := aes.NewCipher(key)
	return block, preamble, err
}

func (c *aesCipher) decryptCipher(file io.Reader) (cipher.Block, error) {
	header := make([]byte, len(symV1Header))
	if _, err := file.Read(header); err != nil {
		return nil, err
	}
	switch string(header) {
	case symV1Header:
		return c.v1Cipher()
	case symV2Header:
		return c.v2Cipher(file)
	default:
		return nil, fmt.Errorf(
			"invalid file header %q, expected either %q or %q",
			string(header), symV1Header, symV2Header,
		)
	}
}

func (c *aesCipher) v1Cipher() (cipher.Block, error) {
	return aes.NewCipher(c.key)
}

func (c *aesCipher) v2Cipher(file io.Reader) (cipher.Block, error) {
	salt := make([]byte, v2SaltSize)
	if _, err := file.Read(salt); err != nil {
		return nil, err
	}
	key, err := c.v2Key(salt)
	if err != nil {
		return nil, err
	}
	return aes.NewCipher(key)
}

func (c *aesCipher) v2Key(salt []byte) ([]byte, error) {
	return scrypt.Key(c.key, salt, v2KeyCost, 8, 1, 32)
}
