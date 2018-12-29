package tests

import (
	"../utils"
	"../TorClient"
	"../dirserver"
	"../keyLibrary"
	"crypto/rsa"
	"fmt"
	"log"
	"strconv"
	"testing"
)

func TestNewDirServer(t *testing.T) {

	dirserver.SaveKeysOnDisk()

	pubKey, err := keyLibrary.LoadPublicKey("../dirserver/public.pem")
	checkError(err)

	ds := dirserver.NewDirServer("localhost", "8001", "8002", "8003")
	if ds.Ip != "localhost" {
		t.Errorf("Incorrect Ip: " + ds.Ip)
	} else if ds.PortForTN != "8001" {
		t.Errorf("Incorrect PortForTN: " + ds.PortForTN)
	} else if ds.PortForTC != "8002" {
		t.Errorf("Incorrect PortForTC: " + ds.PortForTC)
	} else if ds.PortForHB != "8003" {
		t.Errorf("Incorrect PortForHB: " + ds.PortForHB)
	}

	cipherText, _ := keyLibrary.PubKeyEncrypt(pubKey, []byte("Hello World"))
	decryptedBytes, err := keyLibrary.PrivKeyDecrypt(ds.PriKey, cipherText)
	checkError(err)

	plainText := string(decryptedBytes)
	if plainText != "Hello World" {
		t.Errorf("Unmatched decrypted message: " + plainText)
	}
}


func TestListenAndServeTN(t *testing.T) {

	ds := dirserver.NewDirServer("localhost", "8001", "8002", "8003")
	go ds.ListenAndServeTC()

	numTNs := 5
	for i := 0; i < numTNs; i++ {
		addr := "127.0.0.1:000" + strconv.Itoa(i)
		key, _:= keyLibrary.GeneratePrivPubKey()
		ds.TNs[addr] = key.PublicKey
	}

	TNs := sendTCRequest(uint16(numTNs))
	for addr, key := range TNs {
		fmt.Println(addr, " ", key)
	}
	if len(TNs) != numTNs {
		t.Errorf("DS didn't provide enough TNs.")
		fmt.Println("Requested: ", numTNs, "\nGot: ", len(TNs))
	}
}

func sendTCRequest(numTNs uint16) map[string]rsa.PublicKey {
	key, err := keyLibrary.LoadPublicKey("../dirserver/public.pem")
	checkError(err)

	clientConfig := utils.ClientConfig{
		DSPublicKey:  	*key,
		MaxNumNodes: 	numTNs,
		DSIp:			"localhost:8002",
		ServerIp: 		"localhost:8004",
	}

	return TorClient.ContactDsSerer(clientConfig.DSIp, clientConfig.MaxNumNodes, clientConfig.DSPublicKey)
}

func checkError(err error) {
	if err != nil {
		log.Fatal(err)
	}
}


