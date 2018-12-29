package main

import (
	"fmt"
	"os"
	"strconv"

	"./tornode"
)

func main() {
	args := os.Args[1:]

	if !(len(args) == 0 || len(args) == 4) {
		fmt.Println("Usage: go run tn/main.go [dsIPPort] [listenIPPort] [fdListenIPPort] [timeOutMillis]")
		return
	}

	dsIPPort := "127.0.0.1:8001"
	listenIPPort := "127.0.0.1:4001"
	fdListenIPPort := "127.0.0.1:4002"
	timeOutMillis := 1000

	if len(args) == 4 {
		dsIPPort = args[0]
		listenIPPort = args[1]
		fdListenIPPort = args[2]
		var err error
		timeOutMillis, err = strconv.Atoi(args[3])
		if err != nil {
			fmt.Println("Invalid timeOutMillis integer")
			return
		}
	}

	tnerr := tornode.InitTorNode(dsIPPort, listenIPPort, fdListenIPPort, timeOutMillis)
	if tnerr != nil {
		fmt.Println(tnerr)
	} else {
		<-make(chan bool)
	}
}
