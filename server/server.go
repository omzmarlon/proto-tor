package main

import (
	"fmt"
	"log"
	"os"

	"./DataServer"
)

func main() {
	var configFile string

	if len(os.Args) == 2 {
		configFile = os.Args[1]
	} else {
		log.Fatal("usage: go run server.go [ConfigFile]")
	}

	server, err := DataServer.Initialize(configFile, "./server/DataServer/private.pem")

	if err != nil {
		fmt.Println("Server failed to start, exiting...")
		fmt.Println(err)
		return
	}

	server.StartService()
}
