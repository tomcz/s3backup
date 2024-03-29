package client

import (
	"errors"
	"log"
	"os"
)

const tempFileSuffix = ".tmp"

type Client struct {
	Hash   Hash
	Cipher Cipher
	Store  Store
}

func (c *Client) GetRemoteFile(remotePath, localPath string) error {
	if err := c.checkPaths(remotePath, localPath); err != nil {
		return err
	}
	if c.Store.IsRemote(localPath) {
		localPath, remotePath = remotePath, localPath
	}

	tempFile := localPath
	if c.Cipher != nil {
		tempFile += tempFileSuffix
		defer remove(tempFile)
	}

	log.Println("Downloading", remotePath, "to", tempFile)
	checksum, cerr := c.Store.DownloadFile(remotePath, tempFile)
	if cerr != nil {
		return cerr
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
	if err := c.checkPaths(remotePath, localPath); err != nil {
		return err
	}
	if c.Store.IsRemote(localPath) {
		localPath, remotePath = remotePath, localPath
	}

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

func (c *Client) checkPaths(remotePath, localPath string) error {
	if c.Store.IsRemote(remotePath) && c.Store.IsRemote(localPath) {
		return errors.New("cannot have two remote paths")
	}
	if !c.Store.IsRemote(remotePath) && !c.Store.IsRemote(localPath) {
		return errors.New("cannot have two local paths")
	}
	return nil
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
