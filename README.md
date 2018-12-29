# Tor Network - Protect Your Identity!
This project builds a prototype Tor network to demonstrate the idea of using intermediate Tor nodes to protect the identity (IP) of a client.  
The **directory server** tracks existing Tor nodes in the network.  
The **data server** is a servers a simple key-value store, developed solely for the purpose of demonstrating our prototype Tor network. We assume that the client only visit our data server.  
The **Tor client** is also developed for prototype demonstration. It sends a request into the Tor network that will eventually reach the data server. We assume that the users only use our client program to visit our Tor network.  
The **Tor nodes** are the individual nodes that make up our anonymity network.  

## How to start Diretory_Server
`go run dirserver/dirserver.go [Ip] [PortForTN] [PortForTC]`

(Default: Ip=localhost, PortForTN=8001, PortForTC=8002)
   
## How to start Data Server
`go run server/server.go config/server.json`


## How to run Tor client
`go run client/client.go config/client.json keyToFetch`

## How to run Tor node
`go run tn/main.go [dsIPPort] [listenIPPort] [fdListenIPPort] [timeOutMillis]`

(Default: dsIPPort=127.0.0.1:8001, listenIPPort=127.0.0.1:4001, fdListenIPPort=127.0.0.1:4002, timeOutMillis=1000)

## How to generate ShiViz log file
Make sure you have installed GoVector: `go get -u github.com/DistributedClocks/GoVector`

Make sure you have removed all previous logs: `rm *.txt`

`$GOPATH/bin/GoVector --log_type shiviz --log_dir . --outfile tor-net-vec-log.log`

## This is a collaboration project with:

https://github.com/Minxing-Wang

https://github.com/kanchine

https://github.com/J0YAL
