package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/scrypt"

	"github.com/tomcz/s3backup/v2/internal/client"
)

const (
	v2SaltSize = 16
	v3SaltSize = 16
)

type aesCipher struct {
	key []byte
	use string
}

func NewAESCipher(secretKey string) (client.Cipher, error) {
	secretKey = strings.TrimSpace(secretKey)
	if secretKey == "" {
		return nil, fmt.Errorf("cannot use a blank secret key")
	}
	key, err := base64.StdEncoding.DecodeString(secretKey)
	if err == nil && len(key) == 32 {
		return &aesCipher{
			key: key,
			use: symV1Header,
		}, nil
	}
	return &aesCipher{
		key: []byte(secretKey),
		use: symV3Header,
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
	if c.use == symV1Header {
		return c.v1EncryptCipher()
	}
	// scrypt (i.e. symV2Header) key derivation for encryption keys
	// has been replaced by argon2 (i.e. symV3Header). We still support
	// scrypt-derived decryption keys so that we can read older archives.
	return c.v3EncryptCipher()
}

func (c *aesCipher) decryptCipher(file io.Reader) (cipher.Block, error) {
	header := make([]byte, len(symV1Header))
	if _, err := file.Read(header); err != nil {
		return nil, err
	}
	switch string(header) {
	case symV1Header:
		return c.v1DecryptCipher()
	case symV2Header:
		return c.v2DecryptCipher(file)
	case symV3Header:
		return c.v3DecryptCipher(file)
	default:
		return nil, fmt.Errorf(
			"invalid file header %q, expected one of %s, %s, or %s",
			string(header), symV1Header, symV2Header, symV3Header,
		)
	}
}

func (c *aesCipher) v1EncryptCipher() (cipher.Block, []byte, error) {
	preamble := slices.Clone([]byte(symV1Header))
	block, err := aes.NewCipher(c.key)
	return block, preamble, err
}

func (c *aesCipher) v1DecryptCipher() (cipher.Block, error) {
	return aes.NewCipher(c.key)
}

func (c *aesCipher) v2DecryptCipher(file io.Reader) (cipher.Block, error) {
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
	return scrypt.Key(c.key, salt, 1<<20, 8, 1, 32)
}

func (c *aesCipher) v3EncryptCipher() (cipher.Block, []byte, error) {
	salt := randomBytes(v3SaltSize)
	preamble := slices.Concat([]byte(symV3Header), salt)
	block, err := aes.NewCipher(c.v3Key(salt))
	return block, preamble, err
}

func (c *aesCipher) v3DecryptCipher(file io.Reader) (cipher.Block, error) {
	salt := make([]byte, v3SaltSize)
	if _, err := file.Read(salt); err != nil {
		return nil, err
	}
	key := c.v3Key(salt)
	return aes.NewCipher(key)
}

func (c *aesCipher) v3Key(salt []byte) []byte {
	return argon2.IDKey(c.key, salt, 1, 64*1024, 4, 32)
}
