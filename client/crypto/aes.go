package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"os"

	"github.com/tomcz/s3backup/client"
	"github.com/tomcz/s3backup/utils"
)

type aesCipher struct {
	key []byte
}

func NewAESCipher(secretKey string) (client.Cipher, error) {
	key, err := parseAESKey(secretKey)
	if err != nil {
		return nil, err
	}
	return &aesCipher{key}, nil
}

func (c *aesCipher) Encrypt(plainTextFile, cipherTextFile string) error {
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return err
	}

	iv, err := utils.Random(block.BlockSize())
	if err != nil {
		return err
	}

	outFile, err := os.Create(cipherTextFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	if _, err = outFile.Write([]byte(symKeyVersion)); err != nil {
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
	block, err := aes.NewCipher(c.key)
	if err != nil {
		return err
	}

	inFile, err := os.Open(cipherTextFile)
	if err != nil {
		return err
	}
	defer inFile.Close()

	preamble := make([]byte, len(symKeyVersion))
	if _, err = inFile.Read(preamble); err != nil {
		return err
	}
	if !bytes.Equal(preamble, []byte(symKeyVersion)) {
		return fmt.Errorf("file does not start with %v", symKeyVersion)
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
