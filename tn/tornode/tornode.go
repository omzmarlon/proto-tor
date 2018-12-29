package tornode

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"time"

	"../../keyLibrary"
	"../../utils"
	"github.com/DistributedClocks/GoVector/govec"
)

type TorNode struct {
	PrivateKey    *rsa.PrivateKey
	ListenIPPort  string
	fd            utils.FD
	timeoutMillis int
}

func InitTorNode(dsIPPort string, listenIPPort string, fdListenIPPort string, timeoutMillis int) error {
	fmt.Println("==========================================================")
	fmt.Printf("Initalizing Tor node with DS: %s, listening at: %s, fdlib listening at %s, timeout in milliseconds: %d\n", dsIPPort, listenIPPort, fdListenIPPort, timeoutMillis)

	vecLogger := govec.InitGoVector("tor-node-"+listenIPPort, "tor-node-"+listenIPPort, govec.GetDefaultConfig())

	// Initialize variables
	privateKey, pkerror := keyLibrary.GeneratePrivPubKey()
	if pkerror != nil {
		fmt.Printf("Could not init tor node. Failed to generate private key: %s\n", pkerror)
		return pkerror
	}

	// load necessary keys
	publicKey := &privateKey.PublicKey

	// start failure detector
	source := rand.NewSource(time.Now().UnixNano())
	rand := rand.New(source)
	epochNonce := rand.Uint64()
	fd, _, fdliberr := utils.Initialize(epochNonce, 50)
	if fdliberr != nil {
		fmt.Printf("TorNode: failed to start fdlib for error: %s\n", fdliberr)
		return fdliberr
	}
	fdresErr := fd.StartResponding(fdListenIPPort)
	if fdresErr != nil {
		fmt.Printf("TorNode: failed to start responding for error: %s\n", fdresErr)
		return fdresErr
	}

	// join network
	dsstatus, dserror := contactDS(dsIPPort, listenIPPort, fdListenIPPort, publicKey, vecLogger)
	if dserror != nil {
		fmt.Printf("TorNode: Could not contact DS to join tor network for error: %s\n", dserror)
		return dserror
	}
	if !dsstatus {
		return errors.New("TorNode: Network join rejected by DS")
	}

	laddr, laddrErr := net.ResolveTCPAddr("tcp", listenIPPort)
	if laddrErr != nil {
		fmt.Printf("TorNode: Could not resolve listen address for error: %s\n", laddrErr)
		return laddrErr
	}
	listener, lerr := net.ListenTCP("tcp", laddr)
	if lerr != nil {
		fmt.Printf("TorNode: Could not start TCP listening for error: %s\n", lerr)
		return lerr
	}

	fmt.Printf("Tor Node successfully initialized! Kicking off onion handler daemon...\n\n\n")
	go onionHandler(listener, privateKey, timeoutMillis, vecLogger)

	return nil
}
