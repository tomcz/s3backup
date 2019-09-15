package crypto

import (
	"bytes"
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/tomcz/s3backup/tools"
)

type rsaCipher struct {
	block *pem.Block
}

func NewRSACipher(pemKeyFile string) (Cipher, error) {
	buf, err := ioutil.ReadFile(pemKeyFile)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(buf)
	if block == nil {
		return nil, fmt.Errorf("%v does not contain a PEM block", pemKeyFile)
	}
	return &rsaCipher{block}, nil
}

func (c *rsaCipher) Encrypt(plainTextFile, cipherTextFile string) error {
	pubKey, err := c.decodePublicKey()
	if err != nil {
		return err
	}

	aesKey, err := GenerateAESKey()
	if err != nil {
		return err
	}

	encAesKey, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pubKey, aesKey, nil)
	if err != nil {
		return err
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}

	iv, err := tools.Random(block.BlockSize())
	if err != nil {
		return err
	}

	outFile, err := os.Create(cipherTextFile)
	if err != nil {
		return err
	}
	defer outFile.Close()

	if _, err := outFile.Write([]byte(asymKeyVersion)); err != nil {
		return err
	}
	if err := binary.Write(outFile, binary.LittleEndian, uint64(len(encAesKey))); err != nil {
		return err
	}
	if _, err := outFile.Write(encAesKey); err != nil {
		return err
	}
	if _, err := outFile.Write(iv); err != nil {
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

func (c *rsaCipher) Decrypt(cipherTextFile, plainTextFile string) error {
	privKey, err := c.decodePrivateKey()
	if err != nil {
		return err
	}

	inFile, err := os.Open(cipherTextFile)
	if err != nil {
		return err
	}
	defer inFile.Close()

	preamble := make([]byte, len(asymKeyVersion))
	if _, err := inFile.Read(preamble); err != nil {
		return err
	}
	if !bytes.Equal(preamble, []byte(asymKeyVersion)) {
		return fmt.Errorf("file does not start with %v", asymKeyVersion)
	}

	var encAesKeyLen uint64
	if err := binary.Read(inFile, binary.LittleEndian, &encAesKeyLen); err != nil {
		return err
	}
	encAesKey := make([]byte, encAesKeyLen)
	if _, err := inFile.Read(encAesKey); err != nil {
		return err
	}
	aesKey, err := privKey.Decrypt(rand.Reader, encAesKey, &rsa.OAEPOptions{Hash: crypto.SHA256})
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return err
	}

	iv := make([]byte, block.BlockSize())
	if _, err := inFile.Read(iv); err != nil {
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

func (c *rsaCipher) decodePublicKey() (*rsa.PublicKey, error) {
	if c.block.Type != "PUBLIC KEY" {
		return nil, fmt.Errorf("bad PEM block: expected PUBLIC KEY, actual %v", c.block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(c.block.Bytes)
	if err != nil {
		return nil, err
	}
	pubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("PEM block does not contain a RSA Public Key")
	}
	return pubKey, nil
}

func (c *rsaCipher) decodePrivateKey() (*rsa.PrivateKey, error) {
	if c.block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("bad PEM block: expected PRIVATE KEY, actual %v", c.block.Type)
	}
	return x509.ParsePKCS1PrivateKey(c.block.Bytes)
}
