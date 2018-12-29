package tests

import (
	"../client/TorClient"
	"../keyLibrary"
	"../server/DataServer"
	"../utils"
	"crypto/rsa"
	"github.com/DistributedClocks/GoVector/govec"
	"net"
	"testing"
	"time"
)

func TestServerInit(t *testing.T) {
	server, err := DataServer.Initialize("test.json", "../server/DataServer/private.pem")

	if err != nil {
		t.Errorf("Server initializetion failed")
	}

	key1 := "a"
	valExpected := "test1"

	if val, ok := server.DataBase[key1]; !ok {
		t.Errorf("Server database key %s not found", key1)
	} else {
		if val != valExpected {
			t.Errorf("Server database value for key %s actual: %s  Expected: %s", key1, val, valExpected)
		}
	}

	key2 := "b"
	valExpected = "test2"

	if val, ok := server.DataBase[key2]; !ok {
		t.Errorf("Server database key %s not found", key2)
	} else {
		if val != valExpected {
			t.Errorf("Server database value for key %s actual: %s  Expected: %s", key1, val, valExpected)
		}
	}

	key3 := "c"
	valExpected = "test3"

	if val, ok := server.DataBase[key3]; !ok {
		t.Errorf("Server database key %s not found", key3)
	} else {
		if val != valExpected {
			t.Errorf("Server database value for key %s actual: %s  Expected: %s", key1, val, valExpected)
		}
	}

	expectedIpPort := "127.0.0.1:8080"

	if server.IpPort != expectedIpPort {
		t.Errorf("Server ip port mismatch.")
	}
}

func TestServerRequest(t *testing.T) {
	server, _ := DataServer.Initialize("test.json","../server/DataServer/private.pem")
	key := "a"
	expectedValue := "test1"
	go server.StartService()

	time.Sleep(2 * time.Second)

	value, err := sendAndReceive(server.IpPort, server.Key.PublicKey, key)

	if err != nil {
		t.Errorf("Unable to receive response from server.")
	}

	if value != expectedValue {
		t.Errorf("Actual value received %s, expected value is %s", value, expectedValue)
	}
}

func sendAndReceive(serverIpPort string, serverPublicKey rsa.PublicKey, key string) (string, error) {
	tcpLocalAddr, _ := net.ResolveTCPAddr("tcp", "127.0.0.1:8081")

	tcpServerAddr, _ := net.ResolveTCPAddr("tcp", serverIpPort)

	tcpConn, _ := net.DialTCP("tcp", tcpLocalAddr, tcpServerAddr)

	myMap := make(map[string]rsa.PublicKey)

	myMap["server"] = serverPublicKey

	order := []string{"server"}

	onionbytes, symKeys := CreateEncryptedRequest(order, myMap, key)

	serverVectorLogger := govec.InitGoVector("data-server", "data-server", govec.GetDefaultConfig())
	_, _ = utils.TCPWrite(tcpConn, onionbytes,serverVectorLogger, "Responded to client request")

	clientVectorLogger := govec.InitGoVector("fake-client", "client", govec.GetDefaultConfig())
	res, _ := utils.TCPRead(tcpConn, clientVectorLogger, "Response from the server")

	for _, key := range symKeys {
		var err error
		res, err = keyLibrary.SymmKeyDecrypt(res, key)
		if err != nil {
			return "", err
		}
	}

	var resp utils.Response

	err := utils.UnMarshall(res, &resp)

	return resp.Value, err
}

func CreateEncryptedRequest(nodeOrder []string, tnMap map[string]rsa.PublicKey, reqKey string) ([]byte, [][]byte) {

	symKeys := make([][]byte, 0)

	ServerSymKey := keyLibrary.GenerateSymmKey()
	request, _ := utils.Marshall(utils.Request{Key: reqKey, SymmKey: ServerSymKey})

	symKeys = append(symKeys, ServerSymKey)

	encryptedRequest := TorClient.EncryptPayload(request, tnMap[nodeOrder[len(nodeOrder)-1]])

	marshalledRequest, _ := utils.Marshall(encryptedRequest)

	return marshalledRequest,symKeys
}
