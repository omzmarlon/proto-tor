package tornode

import (
	"crypto/rsa"
	"net"

	"github.com/DistributedClocks/GoVector/govec"

	"../../utils"
)

func contactDS(dsIPPort string, TorIPPort string, fdlibIPPort string, pubKey *rsa.PublicKey, vecLogger *govec.GoLog) (bool, error) {
	var laddr, raddr *net.TCPAddr
	var addrErr error
	laddr, addrErr = net.ResolveTCPAddr("tcp", ":0")
	raddr, addrErr = net.ResolveTCPAddr("tcp", dsIPPort)
	if addrErr != nil {
		return false, addrErr
	}
	conn, connErr := net.DialTCP("tcp", laddr, raddr)
	if connErr != nil {
		return false, connErr
	}

	request := utils.NetworkJoinRequest{
		TorIpPort:   TorIPPort,
		FdlibIpPort: fdlibIPPort,
		PubKey:      *pubKey,
	}
	payload, merr := utils.Marshall(request)
	if merr != nil {
		return false, merr
	}
	_, werr := utils.TCPWrite(conn, payload, vecLogger, "Contact DS to join network")
	if werr != nil {
		return false, werr
	}
	responsePayload, rerr := utils.TCPRead(conn, vecLogger, "Confirmed joined network successfully")
	if rerr != nil {
		return false, rerr
	}
	response := &utils.NetworkJoinResponse{}
	umerr := utils.UnMarshall(responsePayload, response)
	if umerr != nil {
		return false, umerr
	}
	return response.Status, nil
}
