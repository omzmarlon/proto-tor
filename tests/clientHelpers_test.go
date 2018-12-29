package tests

import (
	"../client/TorClient"
	"../keyLibrary"
	"../utils"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"testing"
)

func TestCreateOnionMessage(t *testing.T) {

	t1Key, _ := keyLibrary.GeneratePrivPubKey()
	t2Key, _ := keyLibrary.GeneratePrivPubKey()
	t3Key, _ := keyLibrary.GeneratePrivPubKey()
	serverKey, _ := keyLibrary.GeneratePrivPubKey()

	myMap := make(map[string]rsa.PublicKey)

	myMap["1"] = t1Key.PublicKey
	myMap["2"] = t2Key.PublicKey
	myMap["3"] = t3Key.PublicKey
	myMap["server"] = serverKey.PublicKey

	order := []string{"1", "2", "3", "server"}

	onionbytes, _ := TorClient.CreateOnionMessage(order, myMap, "Hello World")

	var encryptedOnionBytes [][]byte

	err := utils.UnMarshall(onionbytes, &encryptedOnionBytes)
	if err != nil {
		fmt.Println(err)
	}

	var decryptedOnionBytes []byte

	for i := range encryptedOnionBytes {
		decryptedBytePiece, err := keyLibrary.PrivKeyDecrypt(t1Key, encryptedOnionBytes[i])
		if err != nil {
			fmt.Println("failed decrypt")
		}
		decryptedOnionBytes = append(decryptedOnionBytes, decryptedBytePiece...)
	}

	var t1OnionMessage utils.Onion
	err = json.Unmarshal(decryptedOnionBytes, &t1OnionMessage)
	if err != nil {
		fmt.Println("here", err)
	}
	fmt.Println(t1OnionMessage)

	/////////////////////////////////// 2ND ONION MESSAGE ///////////////////////

	var unmarshalledOnionBytes2 [][]byte

	err = utils.UnMarshall(t1OnionMessage.Payload, &unmarshalledOnionBytes2)
	if err != nil {
		fmt.Println("error here", err)
	}

	var decryptedOnionBytes2 []byte

 	for i := range unmarshalledOnionBytes2 {
		decryptedBytePiece, err := keyLibrary.PrivKeyDecrypt(t2Key, unmarshalledOnionBytes2[i])
		if err != nil {
			fmt.Println("failed decrypt")
		}
		decryptedOnionBytes2 = append(decryptedOnionBytes2, decryptedBytePiece...)
	}

 	var t2OnionMessage utils.Onion

 	utils.UnMarshall(decryptedOnionBytes2, &t2OnionMessage)

 	fmt.Println( t2OnionMessage)

	/////////////////////////////////// 3rd ONION MESSAGE ///////////////////////

	var unmarshalledOnionBytes3 [][]byte

	err = utils.UnMarshall(t2OnionMessage.Payload, &unmarshalledOnionBytes3)
	if err != nil {
		fmt.Println("error here", err)
	}

	var decryptedOnionBytes3 []byte

	for i := range unmarshalledOnionBytes3 {
		decryptedBytePiece, err := keyLibrary.PrivKeyDecrypt(t3Key, unmarshalledOnionBytes3[i])
		if err != nil {
			fmt.Println("failed decrypt")
		}
		decryptedOnionBytes3 = append(decryptedOnionBytes3, decryptedBytePiece...)
	}

	var t3OnionMessage utils.Onion

	utils.UnMarshall(decryptedOnionBytes3, &t3OnionMessage)

	fmt.Println( t3OnionMessage)

	/////////////////////////////////// 4th ONION MESSAGE ///////////////////////

	var serverBytes [][]byte

	err = utils.UnMarshall(t3OnionMessage.Payload, &serverBytes)
	if err != nil {
		fmt.Println("error here", err)
	}

	var decryptedServerBytes []byte

	for i := range serverBytes {
		decryptedBytePiece, err := keyLibrary.PrivKeyDecrypt(serverKey, serverBytes[i])
		if err != nil {
			fmt.Println("failed decrypt")
		}
		decryptedServerBytes = append(decryptedServerBytes, decryptedBytePiece...)
	}

	var serverMessage utils.Request

	utils.UnMarshall(decryptedServerBytes, &serverMessage)

	fmt.Println(serverMessage)

}


/*

func TestDecryptOnionRes(t *testing.T) {
	//creating 4 level onion message

	serverKey := keyLibrary.GenerateSymmKey()
	t3Key := keyLibrary.GenerateSymmKey()
	t2Key := keyLibrary.GenerateSymmKey()
	t1Key := keyLibrary.GenerateSymmKey()

	symmKeys := [][]byte{t1Key, t2Key, t3Key, serverKey}

	response := utils.Response{Value:"Hello World"}

	t3Onion := utils.Onion{}
	marshalledResonse, _ := utils.Marshall(response)
	t3Onion.Payload, _ = keyLibrary.SymmKeyEncrypt(marshalledResonse, serverKey)

	t2Onion := utils.Onion{}
	marshalledT3Onion, _ := utils.Marshall(t3Onion)
	t2Onion.Payload, _ = keyLibrary.SymmKeyEncrypt(marshalledT3Onion, t3Key)

	t1Onion := utils.Onion{}
	marshalledT2Onion, _ := utils.Marshall(t2Onion)
	t1Onion.Payload, _ = keyLibrary.SymmKeyEncrypt(marshalledT2Onion, t2Key)

	endOnion := utils.Onion{}
	marshalledT1Onion, _ := utils.Marshall(t1Onion)
	endOnion.Payload, _ = keyLibrary.SymmKeyEncrypt(marshalledT1Onion, t1Key)

	endOnionBytes, _ := utils.Marshall(endOnion)

	//done creating onion message

	//unwrap union message
	res := TorClient.DecryptServerResponse(endOnionBytes, symmKeys)

	if res != "Hello World" {
		t.Log("FAILED TO GET CORRECT STRING")
	}

func TestDetermineTnOrder(t *testing.T) {

	myMap := make(map[string]rsa.PublicKey)
	key, _ := keyLibrary.GeneratePrivPubKey()

	myMap["1"] = key.PublicKey
	myMap["2"] = key.PublicKey
	myMap["3"] = key.PublicKey
	myMap["4"] = key.PublicKey
	myMap["5"] = key.PublicKey
	myMap["6"] = key.PublicKey
	myMap["7"] = key.PublicKey
	myMap["8"] = key.PublicKey
	myMap["9"] = key.PublicKey
	myMap["10"] = key.PublicKey
	myMap["11"] = key.PublicKey

	order := TorClient.DetermineTnOrder(myMap)
	fmt.Println(order)
	fmt.Println(len(order))
	if len(order) != 11 {
		t.Log("FAILED DETERMINE TN ORDER")
	}
}

func TestEncryptPayload(t *testing.T) {

	t1Key, _ := keyLibrary.GeneratePrivPubKey()

	myBytes := []byte("ekrjhgekrjhgejrghserjghserjkhgserhjgsjhrvidshbewkjfhgjhsgslekjkuesrjhgsekrjdghdkjfghdfkjghsdkjhgsdjrghsdfghj,dfjkhbdfjsbh,jdhfbh,jdfhsbgdf,sjhbkfdhbjldsfgjdhsfgvsjdhbserhldrshvliaeuhluiaerhliauewglieruaghlueirhglaieruhgiluasdfhglkdfjsghlaekfhalkjsdfharlukdghasj,dhfgajshdfgajhdsgfdjs,fgjah,dfgaksjdhfjksdfghjsdfhbadlrubhdaruhadkrhdjrs,f,jadrfb,jarfg,hjagfj,harfgajh,sfgahsjdfgasjdhfgasjdfasdjhfgasjdhfgasjhd,fgas,jhdsjadhfgasdjh,gvurjh")

	encryptedPayload := TorClient.EncryptPayload(myBytes, t1Key.PublicKey)

	fmt.Println(encryptedPayload)
}


}*/