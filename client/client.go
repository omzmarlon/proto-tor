package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"../keyLibrary"
	"../utils"
	"./TorClient"
	"github.com/DistributedClocks/GoVector/govec"
)

func main() {
	configPath := ""

	if len(os.Args)-1 != 2 {
		fmt.Println("please use: go run client.go client.json keyToFetchFromServer")
	}

	configPath = os.Args[1]
	keyToFetch := os.Args[2]

	rawConfig, fileerr := ioutil.ReadFile(configPath)
	if fileerr != nil {
		log.Printf("client.go: Invalid json file: %s\n", fileerr)
		os.Exit(1)
	}
	clientConfig := &utils.ClientConfig{}
	jsonErr := json.Unmarshal(rawConfig, clientConfig)
	if jsonErr != nil {
		log.Printf("client.go: Invalid json file: %s\n", jsonErr)
		os.Exit(1)
	}
	vecLogger := govec.InitGoVector("Client-"+clientConfig.ID, "Client-"+clientConfig.ID, govec.GetDefaultConfig())

	//1. communicate to DS to get the list of tor nodes
	DSPublicKey, keyErr := keyLibrary.LoadPublicKey(clientConfig.DSPublicKeyPath)
	if keyErr != nil {
		panic(keyErr)
	}
	tnMap, dsErr := TorClient.ContactDsSerer(clientConfig.DSIPPort, clientConfig.MaxNumNodes, *DSPublicKey, vecLogger)

	if dsErr != nil {
		fmt.Printf("Could not contact directory server for error: %s\n", dsErr)
		os.Exit(1)
	}

	if uint16(len(tnMap)) < clientConfig.MaxNumNodes {
		fmt.Printf("Directory server didn't send enough tor nodes: needed %d, received: %d\n", clientConfig.MaxNumNodes, len(tnMap))
		os.Exit(1)
	}

	nodeOrder := TorClient.DetermineTnOrder(tnMap)
	fmt.Println("Client: using Tor circuit: ", nodeOrder)
	nodeOrder = append(nodeOrder, clientConfig.ServerIPPort)

	//2. create and send onion
	serverPublicKey, err := keyLibrary.LoadPublicKey(clientConfig.ServerPublicKeyPath)
	if err != nil {
		panic(err)
	}

	tnMap[clientConfig.ServerIPPort] = *serverPublicKey

	fmt.Println("Client: Fetching key: ", keyToFetch)
	onionMessage, symmKeys := TorClient.CreateOnionMessage(nodeOrder, tnMap, keyToFetch)

	res, sendErr := TorClient.SendOnionMessage(nodeOrder[0], onionMessage, symmKeys, vecLogger)
	if sendErr != nil {
		fmt.Printf("Could not send onion message for error: %s\n", sendErr)
		os.Exit(1)
	}

	fmt.Println("Client: We have received this value from the server: ", res)

}
