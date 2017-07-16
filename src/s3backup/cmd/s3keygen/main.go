package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"s3backup/crypto"
	"s3backup/version"
)

var (
	showVersion = flag.Bool("v", false, "Show version and exit")
	keyType     = flag.String("t", "aes", "Key type: aes or rsa")
	privKeyFile = flag.String("priv", "private.pem", "Private key file for rsa key pair")
	pubKeyFile  = flag.String("pub", "public.pem", "Public key file for rsa key pair")
)

func main() {
	flag.Parse()

	if *showVersion {
		fmt.Println(version.Commit())
		os.Exit(0)
	}

	var key string
	var err error

	switch *keyType {
	case "aes":
		key, err = crypto.GenerateAESKeyString()
		if err == nil {
			log.Println(key)
		}
	case "rsa":
		err = crypto.GenerateRSAKeyPair(*privKeyFile, *pubKeyFile)
	default:
		log.Fatalln("Unknown key type:", *keyType)
	}

	if err != nil {
		log.Fatalln("Failed, error is:", err)
	}
}
