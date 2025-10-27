package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"os"

	"golang.org/x/crypto/scrypt"

	"github.com/tomcz/s3backup/v2/internal/client"
)

type aesPwdCipher struct {
	password []byte
	saltSize int
}

func NewAesPwdCipher(password string) client.Cipher {
	return &aesPwdCipher{
		password: []byte(password),
		saltSize: 16,
	}
}

func (a *aesPwdCipher) Encrypt(plainTextFile, cipherTextFile string) error {
	salt := randomBytes(a.saltSize)
	key, err := a.deriveKey(salt)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return err
	}
	iv := randomBytes(block.BlockSize())

	outFile, err := os.Create(cipherTextFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	if _, err = outFile.Write([]byte(pwdKeyVersion)); err != nil {
		return err
	}
	if _, err = outFile.Write(salt); err != nil {
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

func (a *aesPwdCipher) Decrypt(cipherTextFile, plainTextFile string) error {
	inFile, err := os.Open(cipherTextFile)
	if err != nil {
		return err
	}
	defer inFile.Close()

	preamble := make([]byte, len(pwdKeyVersion))
	if _, err = inFile.Read(preamble); err != nil {
		return err
	}
	if !bytes.Equal(preamble, []byte(pwdKeyVersion)) {
		return fmt.Errorf("file does not start with %s", pwdKeyVersion)
	}
	salt := make([]byte, a.saltSize)
	if _, err = inFile.Read(salt); err != nil {
		return err
	}
	key, err := a.deriveKey(salt)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
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

func (a *aesPwdCipher) deriveKey(salt []byte) ([]byte, error) {
	return scrypt.Key(a.password, salt, 1<<20, 8, 1, 32)
}
