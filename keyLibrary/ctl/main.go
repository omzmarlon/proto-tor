package main

import (
	"fmt"
	"os"

	"../../keyLibrary"
)

func main() {
	fmt.Println("Make sure you create necessary directories!")

	args := os.Args[1:]
	if len(args) != 1 {
		panic("Please provide private and public key path")
	}

	key, _ := keyLibrary.GeneratePrivPubKey()
	prierr := keyLibrary.SavePrivateKeyOnDisk(args[0]+"/private.pem", key)
	if prierr != nil {
		panic(prierr)
	}

	puberr := keyLibrary.SavePublicKeyOnDisk(args[0]+"/public.pem", &key.PublicKey)
	if puberr != nil {
		panic(puberr)
	}
	fmt.Println("Key gen successful")
}
