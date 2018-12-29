package TorClient

import (
	"crypto/rsa"
	"math/rand"
	"time"
	"../../keyLibrary"
	"../../utils"
)

const byteSize = 150

//returns a list of symmetrical keys from T1 to Tn
//and the onion message
func CreateOnionMessage(nodeOrder []string, tnMap map[string]rsa.PublicKey, reqKey string) ([]byte, [][]byte) {

	var onionMessage []byte
	var symKeys [][]byte

	ServerSymKey := keyLibrary.GenerateSymmKey()

	request, _ := utils.Marshall(utils.Request{Key: reqKey, SymmKey: ServerSymKey})

	symKeys = append(symKeys, ServerSymKey)

	encryptedRequest := EncryptPayload(request, tnMap[nodeOrder[len(nodeOrder)-1]])

	marshalledRequest, _ := utils.Marshall(encryptedRequest)

	for i := len(nodeOrder) - 2; i > -1; i-- {
		var outerOnionMessage utils.Onion

		symmKey := keyLibrary.GenerateSymmKey()

		outerOnionMessage.SymmKey = symmKey
		symKeys = append([][]byte{symmKey}, symKeys...)

		if i == len(nodeOrder)-2 {
			//this is onion message to the server
			outerOnionMessage.NextIpPort = nodeOrder[len(nodeOrder)-1]

			outerOnionMessage.Payload = marshalledRequest

			marshalledOnion, _ := utils.Marshall(outerOnionMessage)

			encryptedOnion := EncryptPayload(marshalledOnion, tnMap[nodeOrder[len(nodeOrder)-2]])

			finalMarshalledOnion, _ := utils.Marshall(encryptedOnion)

			onionMessage = finalMarshalledOnion

		} else {

			outerOnionMessage.NextIpPort = nodeOrder[i+1]

			nodePublicKey := tnMap[nodeOrder[i]]

			outerOnionMessage.Payload = onionMessage
			marshalledOnion, _ := utils.Marshall(outerOnionMessage)

			encryptedOnion := EncryptPayload(marshalledOnion, nodePublicKey)

			finalMarshalledOnion, _ := utils.Marshall(encryptedOnion)

			onionMessage = finalMarshalledOnion

		}
	}

	return onionMessage, symKeys

}

func EncryptPayload(onionBytes []byte, key rsa.PublicKey) [][]byte {
	var encryptedPayload [][]byte

	counter := 0

	for counter+byteSize-1 < len(onionBytes) {

		encryptedSlice, _ := keyLibrary.PubKeyEncrypt(&key, onionBytes[counter:counter+byteSize])

		encryptedPayload = append(encryptedPayload, encryptedSlice)

		counter += byteSize
	}

	lastEncryptedSlice, _ := keyLibrary.PubKeyEncrypt(&key, onionBytes[counter:])

	encryptedPayload = append(encryptedPayload, lastEncryptedSlice)

	return encryptedPayload
}

func DecryptServerResponse(onionBytes []byte, symmKeys [][]byte) string {

	currBytes := onionBytes

	for i := 0; i < len(symmKeys) - 1; i ++ {

		decryptedOnionBytes, err := keyLibrary.SymmKeyDecrypt(currBytes, symmKeys[i])

		if err != nil {
			panic("can not decrypt onion using symmKey")
		}

		var unmarshalledOnion utils.Onion
		err = utils.UnMarshall(decryptedOnionBytes, &unmarshalledOnion)

		if err != nil {
			panic("can not unmarshal onion")
		}

		currBytes = unmarshalledOnion.Payload
	}

	decryptedResponse, err  := keyLibrary.SymmKeyDecrypt(currBytes, symmKeys[len(symmKeys) - 1])
	if err != nil {
		panic("cant decrypt server response")
	}

	var resObj utils.Response
	utils.UnMarshall(decryptedResponse, &resObj)

	return resObj.Value
}

func DetermineTnOrder(tnMap map[string]rsa.PublicKey) []string {

	keys := getKeysFromMap(tnMap)

	order := make([]string, 0)

	rand.Seed(time.Now().Unix())
	for len(keys) > 1 {
		i := rand.Intn(len(keys) - 1)
		order = append(order, keys[i])

		keys[i] = keys[len(keys)-1]
		keys = keys[:len(keys)-1]
	}

	return append(order, keys[0])
}

func getKeysFromMap(m map[string]rsa.PublicKey) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	return keys
}
