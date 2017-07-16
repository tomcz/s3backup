package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"s3backup/client"
	"s3backup/crypto"
	"s3backup/store"
	"s3backup/version"
)

var (
	showVersion  = flag.Bool("v", false, "Show version and exit")
	doGet        = flag.Bool("get", false, "Get remote file from s3 bucket (send by default)")
	symKey       = flag.String("symKey", "", "Base64-encoded 256-bit symmetric key (optional)")
	pemKeyFile   = flag.String("pemKey", "", "Path to PEM-encoded public or private key file (optional)")
	awsAccessKey = flag.String("accessKey", "", "AWS Access Key ID (if not using default AWS credentials)")
	awsSecretKey = flag.String("secretKey", "", "AWS Secret Key (required if accessKey provided)")
	awsToken     = flag.String("token", "", "AWS Token (required if accessKey provided)")
	awsRegion    = flag.String("region", "", "AWS Region (required if accessKey provided)")
)

func printUsage() {
	fmt.Printf("Usage: %v [options] s3://bucket/objectkey local_file_path\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	remotePath, localPath := parseFlags()

	c, err := newClient()
	if err != nil {
		log.Fatal("Cannot create S3 client, error is:", err)
	}

	if *doGet {
		if err := c.GetRemoteFile(remotePath, localPath); err != nil {
			log.Fatalln("Failed to get remote file, error is:", err)
		}
	} else {
		if err := c.PutLocalFile(remotePath, localPath); err != nil {
			log.Fatalln("Failed to put local file, error is:", err)
		}
	}
	log.Println("Success")
}

func parseFlags() (remotePath, localPath string) {
	flag.Usage = printUsage
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Commit())
		os.Exit(0)
	}

	remotePath = flag.Arg(0)
	localPath = flag.Arg(1)

	if remotePath == "" || localPath == "" {
		fmt.Println("Need both remote_file_path and local_file_path")
		printUsage()
		os.Exit(1)
	}
	return // remotePath, localPath
}

func newClient() (*client.Client, error) {
	s3, err := store.NewS3Store(
		*awsAccessKey,
		*awsSecretKey,
		*awsToken,
		*awsRegion,
	)
	if err != nil {
		return nil, err
	}
	var cipher crypto.Cipher
	if *symKey != "" {
		cipher, err = crypto.NewAESCipher(*symKey)
	}
	if *pemKeyFile != "" {
		cipher, err = crypto.NewRSACipher(*pemKeyFile)
	}
	if err != nil {
		return nil, err
	}
	return &client.Client{
		Hash:   crypto.NewHash(),
		Cipher: cipher,
		Store:  s3,
	}, nil
}
