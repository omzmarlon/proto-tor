package DataServer

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sync"

	"github.com/DistributedClocks/GoVector/govec"

	"../../keyLibrary"
	"../../utils"
)

const TCP_PROTO = "tcp"

type Server struct {
	Key          *rsa.PrivateKey   // Private key of the server, the public key is also in this data structure.
	IpPort       string            // The ip port the server will be listening for connection on.
	DataBase     map[string]string // The key value pair this database stores.
	LockDataBase *sync.Mutex       // Lock to ensure synchronized database access.
	VecLogger    *govec.GoLog
}

type Config struct {
	IncomingTcpAddr string            // The ip port the server will be listening for connection on
	DataBase        map[string]string // The key value pair for the data base
}

func Initialize(configFile string, privateKeyFile string) (*Server, error) {

	jsonFile, err := os.Open(configFile)

	defer func() {
		err := jsonFile.Close()

		if err != nil {
			fmt.Print("Server init: json config file closing failed, continue.")
		}
	}()

	if err != nil {
		fmt.Println("Server init: Error opening the configuration file, please try again.")
		return nil, err
	}

	configData, err := ioutil.ReadAll(jsonFile)

	if err != nil {
		fmt.Println("Server init: Error reading the configuration file, please try again")
		return nil, err
	}

	var config Config
	err = json.Unmarshal(configData, &config)

	privateKey, err := keyLibrary.LoadPrivateKey(privateKeyFile)

	vecLogger := govec.InitGoVector("data-server", "data-server", govec.GetDefaultConfig())

	return &Server{privateKey, config.IncomingTcpAddr, config.DataBase, &sync.Mutex{}, vecLogger}, err
}

func (s *Server) StartService() {
	localTcpAddr, err := net.ResolveTCPAddr(TCP_PROTO, s.IpPort)

	if err != nil {
		fmt.Println("Listener creation failed, please try again.")
		return
	}

	listener, err := net.ListenTCP(TCP_PROTO, localTcpAddr)

	for {
		fmt.Println("Start accepting connections at:", s.IpPort)
		tcpConn, err := listener.AcceptTCP()
		if err != nil {
			fmt.Println("TCP connection failed with client:", tcpConn.RemoteAddr().String())
			continue
		} else {
			fmt.Println("Incoming connection established with client:", tcpConn.RemoteAddr().String())
		}

		go s.connectionHandler(tcpConn)
	}
}

func (s *Server) connectionHandler(conn *net.TCPConn) {
	// Note connection will be closed by the TN.

	reqEncrypt, err := utils.TCPRead(conn, s.VecLogger, "Received client request")

	if err != nil {
		fmt.Println("Server handler: reading data from connection failed")
		return
	}

	req := unmarshalServerRequest(reqEncrypt, s.Key)

	var resp utils.Response
	s.LockDataBase.Lock()
	if val, ok := s.DataBase[req.Key]; ok {
		resp.Value = val
	}
	s.LockDataBase.Unlock()

	respData, err := json.Marshal(&resp)
	if err != nil {
		fmt.Println("Server handler: response marshaling failed")
		return
	}

	encryptedData, err := keyLibrary.SymmKeyEncrypt(respData, req.SymmKey)

	_, err = utils.TCPWrite(conn, encryptedData, s.VecLogger, "Responded to client request")

	fmt.Println("Server response sent to:", conn.RemoteAddr())

	if err != nil {
		fmt.Println("Server handler: response write failed")
		return
	}

	//if n != len(encryptedData) {
	//	fmt.Println("Server handler: incorrect number of bytes written to the connection")
	//	return
	//}
}

func unmarshalServerRequest(data []byte, serverKey *rsa.PrivateKey) utils.Request {

	var serverBytes [][]byte

	err := utils.UnMarshall(data, &serverBytes)
	if err != nil {
		fmt.Println("Error unmarshal client requests bytes:", err)
	}

	var decryptedServerBytes []byte

	for i := range serverBytes {
		decryptedBytePiece, err := keyLibrary.PrivKeyDecrypt(serverKey, serverBytes[i])
		if err != nil {
			fmt.Println("failed to decrypt client requests:", err)
		}
		decryptedServerBytes = append(decryptedServerBytes, decryptedBytePiece...)
	}

	var serverMessage utils.Request

	err = utils.UnMarshall(decryptedServerBytes, &serverMessage)

	if err != nil {
		fmt.Println("Error unmarshal client requests:", err)
	}

	return serverMessage
}
