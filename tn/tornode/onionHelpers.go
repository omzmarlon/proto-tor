package tornode

import (
	"crypto/rsa"

	"../../keyLibrary"
	"../../utils"
)

// peel one layer off of the onion to get payload
// NOTE: assuming one-time circuit usage
// returns next hop IPPort, symmKey assigned, next hop payload
func peelOnion(onionBytes []byte, privateKey *rsa.PrivateKey) (string, []byte, []byte, error) {
	// TODO - marlon
	onion, derr := decryptOnionBytes(onionBytes, privateKey)
	if derr != nil {
		return "", nil, nil, derr
	}
	nextHop := onion.NextIpPort
	symmKey := onion.SymmKey
	payload := onion.Payload
	return nextHop, symmKey, payload, nil
}

// wrap one layer of encryption
func wrapOnion(onionPayload []byte, symmKey []byte) ([]byte, error) {
	onion := utils.Onion{
		NextIpPort: "",
		SymmKey:    nil,
		Payload:    onionPayload,
	}
	onionbytes, merr := utils.Marshall(onion)
	if merr != nil {
		return nil, merr
	}
	return keyLibrary.SymmKeyEncrypt(onionbytes, symmKey)
}

// decrypt received raw bytes into an onion
func decryptOnionBytes(raw []byte, privateKey *rsa.PrivateKey) (*utils.Onion, error) {
	decryptedBytes := make([]byte, 0)
	var encryptedChunks [][]byte
	umerr := utils.UnMarshall(raw, &encryptedChunks)
	if umerr != nil {
		return nil, umerr
	}
	for _, chunk := range encryptedChunks {
		decryptedChunk, derr := keyLibrary.PrivKeyDecrypt(privateKey, chunk)
		if derr != nil {
			return nil, derr
		}
		decryptedBytes = append(decryptedBytes, decryptedChunk...)
	}
	var onion utils.Onion
	umerr = utils.UnMarshall(decryptedBytes, &onion)
	if umerr != nil {
		return nil, umerr
	}
	return &onion, nil
}
