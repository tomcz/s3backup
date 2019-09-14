package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log"
	"os"
)

func GenerateAESKey() ([]byte, error) {
	return Random(32) // 256 bits
}

func GenerateAESKeyString() (string, error) {
	key, err := GenerateAESKey()
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func GenerateRSAKeyPair(privKeyFile, pubKeyFile string) error {
	privKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return err
	}
	privKeyBytes := x509.MarshalPKCS1PrivateKey(privKey)
	if err := writeToPemFile("PRIVATE KEY", privKeyBytes, privKeyFile); err != nil {
		return err
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return err
	}
	return writeToPemFile("PUBLIC KEY", pubKeyBytes, pubKeyFile)
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
	if err := pem.Encode(file, block); err != nil {
		return err
	}

	log.Println("Wrote", keyType, "to", filePath)
	return nil
}
