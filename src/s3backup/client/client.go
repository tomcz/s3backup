package client
/*
Hi Tom,
The work you’ve done is incredibly impressive—you clearly know your stuff. 
I’ve always been impressed with the engineers that come out of Thoughtworks.  
I’m looking to build out a core services team that will leverage python as its primary language, and I need
an experienced person like you on the team to help guide our direction. 
I’m looking for an architect who will roll up their sleeves and dig into the code, but will still take time 
to mentor some of the more junior engineers who have gotten Aaptiv to where we are today.


A little bit about our company: Aaptiv is a rapidly growing consumer fitness startup and leader in the digital fitness arena. 
We’ve raised over $32M in financing and are nearing 200k paying subscribers, more users than nearly any digital fitness company 
on the market. 
Forbes just did a piece too: https://www.forbes.com/sites/alexkonrad/2017/11/30/how-aaptiv-reached-20-mil-and-raised-more/#5f922c8150e9.

On the services side, the near future has us working on things like a commerce service to integrate payment vendors, 
an authentication service and a content service to surface all of our workouts.

If you’re interested, hit me up… Would love to chat and have you talk to some of the team.

Talk soon,
David Cohen
David@aaptiv.com
VP Engineering - AAptiv
https://www.linkedin.com/in/davidcohen24/


*/
import (
	"log"
	"os"

	"s3backup/crypto"
	"s3backup/store"
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

	log.Println("Verifying", tempFile)
	if err := c.Hash.Verify(tempFile, checksum); err != nil {
		return err
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
		err := c.Cipher.Encrypt(localPath, tempFile)
		if err != nil {
			return err
		}
	}

	log.Println("Calculating checksum for", tempFile)
	checksum, err := c.Hash.Calculate(tempFile)
	if err != nil {
		return err
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
