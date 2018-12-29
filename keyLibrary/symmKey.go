package keyLibrary

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

func GenerateSymmKey() []byte {
	key := make([]byte, 32)

	rand.Read(key)
	return key

}

func SymmKeyEncrypt(plaintext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("error creating new cipher in symmKey encrypt")
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println("error creating new gcm in symmKey encrypt")
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println("error creating nonce in symmKey encrypt")
		return nil, err
	}

	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func SymmKeyDecrypt(ciphertext []byte, key []byte) ([]byte, error) {
	c, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println("error creating new cipher in symmKey decrypt")
		return nil, err
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println("error creating new gcm in symmKey decrypt")
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.New("ciphertext too short")
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

func SymmKeyEncryptBase64(plaintext []byte, key []byte) (base64Ciphertext []byte, err error) {

	cipherText, err := SymmKeyEncrypt(plaintext, key)
	if err != nil {
		return nil, err
	}

	base64Ciphertext = make([]byte, base64.RawStdEncoding.EncodedLen(len(cipherText)))
	base64.RawStdEncoding.Encode(base64Ciphertext, cipherText)

	return
}

func SymmKeyDecryptBase64(base64Ciphertext []byte, key []byte) (plaintext []byte, err error) {

	ciphertext := make([]byte, base64.RawStdEncoding.DecodedLen(len(base64Ciphertext)))
	_, err = base64.RawStdEncoding.Decode(ciphertext, base64Ciphertext)
	if err != nil {
		return nil, err
	}

	return SymmKeyDecrypt(ciphertext, key)
}

