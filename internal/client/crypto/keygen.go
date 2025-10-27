package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"strings"
)

const (
	symKeyVersion  = "BSKv1"
	pwdKeyVersion  = "BSKv2"
	asymKeyVersion = "BAKv1"
	rsaPublicKey   = "PUBLIC KEY"
	rsaPrivateKey  = "PRIVATE KEY"
)

func randomBytes(length int) []byte {
	buf := make([]byte, length)
	if _, err := rand.Read(buf); err != nil {
		panic(err) // Read should always succeed according to sdk docs
	}
	return buf
}

func GenerateAESKey() []byte {
	return randomBytes(32) // 256 bits
}

func GenerateAESKeyString() string {
	return base64.StdEncoding.EncodeToString(GenerateAESKey())
}

func parseAESKey(secretKey string) ([]byte, error) {
	if strings.TrimSpace(secretKey) == "" {
		return nil, fmt.Errorf("cannot use blank secret key")
	}
	key, err := base64.StdEncoding.DecodeString(secretKey)
	if err != nil {
		// assume the key should be hashed instead
		sum := sha256.Sum256([]byte(secretKey))
		key = sum[:]
	}
	if len(key) != 32 {
		// key is not quite right so we hash it
		sum := sha256.Sum256(key)
		key = sum[:]
	}
	return key, nil
}

func GenerateRSAKeyPair(privKeyFile, pubKeyFile string) error {
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	if err = writeToPemFile(rsaPrivateKey, privKeyBytes, privKeyFile); err != nil {
		return err
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return err
	}
	return writeToPemFile(rsaPublicKey, pubKeyBytes, pubKeyFile)
}

func decodePublicKey(block *pem.Block) (*rsa.PublicKey, error) {
	if block.Type != rsaPublicKey {
		return nil, fmt.Errorf("bad PEM block: expected %s, actual %s", rsaPublicKey, block.Type)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	pubKey, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("bad PEM block: expected *rsa.PublicKey, actual %T", pub)
	}
	return pubKey, nil
}

func decodePrivateKey(block *pem.Block) (*rsa.PrivateKey, error) {
	if block.Type != rsaPrivateKey {
		return nil, fmt.Errorf("bad PEM block: expected %s, actual %s", rsaPrivateKey, block.Type)
	}
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func writeToPemFile(keyType string, keyBytes []byte, filePath string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	block := &pem.Block{
		Type:  keyType,
		Bytes: keyBytes,
	}
	if err = pem.Encode(file, block); err != nil {
		return err
	}

	log.Println("Wrote", keyType, "to", filePath)
	return nil
}

func readFromPemFile(filePath string) (*pem.Block, error) {
	buf, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(buf)
	if block == nil {
		return nil, fmt.Errorf("%s does not contain a PEM block", filePath)
	}
	return block, nil
}
