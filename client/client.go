package client

import (
	"log"
	"os"

	"github.com/tomcz/s3backup/crypto"
	"github.com/tomcz/s3backup/store"
)

const tempFileSuffix = ".tmp"

type Client struct {
	Hash   crypto.Hash
	Cipher crypto.Cipher
	Store  store.Store
}

func (c *Client) GetRemoteFile(remotePath, localPath string) error {
	tempFile := localPath

	if c.Cipher != nil {
		tempFile += tempFileSuffix
		defer remove(tempFile)
	}

	log.Println("Downloading", remotePath, "to", tempFile)
	checksum, err := c.Store.DownloadFile(remotePath, tempFile)
	if err != nil {
		return err
	}

	if c.Hash != nil {
		log.Println("Verifying", tempFile)
		if err := c.Hash.Verify(tempFile, checksum); err != nil {
			return err
		}
	}

	if c.Cipher != nil {
		log.Println("Decrypting", tempFile, "to", localPath)
		if err := c.Cipher.Decrypt(tempFile, localPath); err != nil {
			remove(localPath)
			return err
		}
	}
	return nil
}

func (c *Client) PutLocalFile(remotePath, localPath string) error {
	tempFile := localPath

	if c.Cipher != nil {
		tempFile += tempFileSuffix
		defer remove(tempFile)

		log.Println("Encrypting", localPath, "to", tempFile)
		if err := c.Cipher.Encrypt(localPath, tempFile); err != nil {
			return err
		}
	}

	var checksum string
	if c.Hash != nil {
		log.Println("Calculating checksum for", tempFile)
		hash, err := c.Hash.Calculate(tempFile)
		if err != nil {
			return err
		}
		checksum = hash
	}

	log.Println("Uploading", tempFile, "as", remotePath)
	return c.Store.UploadFile(remotePath, tempFile, checksum)
}

func remove(filePath string) {
	if _, err := os.Stat(filePath); os.IsNotExist(err) {
		return // no need to remove a file that doesn't exist
	}
	log.Println("Removing", filePath)
	if err := os.Remove(filePath); err != nil {
		log.Printf("NOTE: unable to remove %v: %v\n", filePath, err)
	}
}
