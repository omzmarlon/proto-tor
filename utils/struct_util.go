package utils

import "crypto/rsa"

type Request struct {
	Key     string
	SymmKey []byte
}

type Response struct {
	Value string
}

type Onion struct {
	NextIpPort string
	SymmKey    []byte
	Payload    []byte
}

type NetworkJoinRequest struct {
	TorIpPort   string
	FdlibIpPort string
	PubKey      rsa.PublicKey
}

type NetworkJoinResponse struct {
	Status bool
}

type DsRequest struct {
	NumNodes uint16
	SymmKey  []byte
}

type DsResponse struct {
	DnMap map[string]rsa.PublicKey
}

type ClientConfig struct {
	ID                  string
	DSPublicKeyPath     string
	ServerPublicKeyPath string
	MaxNumNodes         uint16
	DSIPPort            string
	ServerIPPort        string
}
