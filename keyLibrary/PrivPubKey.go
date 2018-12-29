package keyLibrary

import (
	"bufio"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"../x509"
	"encoding/pem"
	"fmt"
	"os"
)

func GeneratePrivPubKey() (*rsa.PrivateKey, error) {

	key, _ := rsa.GenerateKey(rand.Reader, 2048)

	return key, nil
}

func PubKeyEncrypt(pubKey *rsa.PublicKey, message []byte) ([]byte, error) {

	ciphertext, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		pubKey,
		message,
		nil,
	)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return ciphertext, nil
}

func PrivKeyDecrypt(privKey *rsa.PrivateKey, cipherText []byte) ([]byte, error) {
	plainText, err := rsa.DecryptOAEP(
		sha256.New(),
		rand.Reader,
		privKey,
		cipherText,
		nil,
	)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return plainText, nil
}

func SavePrivateKeyOnDisk(fileName string, key *rsa.PrivateKey) error {

	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	var privateKey = &pem.Block{
		Type:  	"PRIVATE KEY",
		Bytes: 	x509.MarshalPKCS1PrivateKey(key),
	}

	err = pem.Encode(file, privateKey)
	if err != nil {
		return err
	}

	return nil
}

func SavePublicKeyOnDisk(fileName string, key *rsa.PublicKey) error {

	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	var publicKey = &pem.Block{
		Type:  	"PUBLIC KEY",
		Bytes: 	x509.MarshalPKCS1PublicKey(key),
	}

	err = pem.Encode(file, publicKey)
	if err != nil {
		return err
	}

	return nil
}


func LoadPrivateKey(fileName string) (*rsa.PrivateKey, error) {

	pemBytes, err := readPemFile(fileName)
	if err != nil {
		return nil, err
	}

	data, _ := pem.Decode(pemBytes)
	key, err := x509.ParsePKCS1PrivateKey(data.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func LoadPublicKey(fileName string) (*rsa.PublicKey, error) {

	pemBytes, err := readPemFile(fileName)
	if err != nil {
		return nil, err
	}

	data, _ := pem.Decode(pemBytes)
	key, err := x509.ParsePKCS1PublicKey(data.Bytes)
	if err != nil {
		return nil, err
	}

	return key, nil
}

func readPemFile(fileName string) ([]byte, error) {

	file, err := os.Open(fileName)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	fileStat, _ := file.Stat()
	pemBytes := make([]byte, fileStat.Size())
	buffer := bufio.NewReader(file)
	_, err = buffer.Read(pemBytes)
	if err != nil {
		return nil, err
	}

	return pemBytes, nil
}

