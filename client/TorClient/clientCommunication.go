package TorClient

import (
	"crypto/rsa"
	"fmt"
	"net"

	"../../keyLibrary"
	"../../utils"
	"github.com/DistributedClocks/GoVector/govec"
)

func ContactDsSerer(DSIp string, numNodes uint16, dsPublicKey rsa.PublicKey, vecLogger *govec.GoLog) (map[string]rsa.PublicKey, error) {

	conn, connErr := getTCPConnection(DSIp)

	if connErr != nil {
		return nil, connErr
	}

	symmKey := sendReqToDs(numNodes, dsPublicKey, conn, vecLogger)

	return readResFromDs(conn, symmKey, vecLogger), nil

}

func SendOnionMessage(t1 string, onion []byte, symmKeys [][]byte, vecLogger *govec.GoLog) (string, error) {

	conn, connErr := getTCPConnection(t1)

	if connErr != nil {
		return "", connErr
	}
	fmt.Printf("Client: Sending %d bytes onion message\n", len(onion))

	utils.TCPWrite(conn, onion, vecLogger, "Sending onion request to Tor network")

	return readResponse(conn, symmKeys, vecLogger), nil
}

func readResponse(conn *net.TCPConn, symmKeys [][]byte, vecLogger *govec.GoLog) string {

	bytesRead, err := utils.TCPRead(conn, vecLogger, "Received onion response from Tor network")

	if err != nil {
		panic("can not read response from connection")
	}

	return DecryptServerResponse(bytesRead, symmKeys)
}

func sendReqToDs(numNodes uint16, dsPublicKey rsa.PublicKey, conn *net.TCPConn, vecLogger *govec.GoLog) []byte {
	symmKey := keyLibrary.GenerateSymmKey()

	request := utils.DsRequest{numNodes, symmKey}
	reqBytes, err := utils.Marshall(request)

	if err != nil {
		fmt.Println("Bad marshalling")
	}

	encryptedBytes, _ := keyLibrary.PubKeyEncrypt(&dsPublicKey, reqBytes)
	utils.TCPWrite(conn, encryptedBytes, vecLogger, "Contact dir_server for tor nodes")

	return symmKey
}

func readResFromDs(conn *net.TCPConn, symmKey []byte, vecLogger *govec.GoLog) map[string]rsa.PublicKey {
	buf, err := utils.TCPRead(conn, vecLogger, "Received tor nodes from dir_server")

	if err != nil {
		panic("can not read response from DS connection")
	}

	decryptedBytes, err := keyLibrary.SymmKeyDecryptBase64(buf, symmKey)
	if err != nil {
		fmt.Println(err)
		panic("can not decrypt response from DS")
	}

	var dsResponse utils.DsResponse
	err = utils.UnMarshall(decryptedBytes, &dsResponse)
	if err != nil {
		fmt.Println(err)
		panic("readResFromDs: Unmarshalling failed")
	}

	return dsResponse.DnMap
}

func getTCPConnection(ip string) (*net.TCPConn, error) {
	raddr, _ := net.ResolveTCPAddr("tcp", ip)
	return net.DialTCP("tcp", nil, raddr)
}
