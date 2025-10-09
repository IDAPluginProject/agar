package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
)

func encrypt_aes_gcm(plaintext, key, nonce []byte) ([]byte, error) {
	// AES-GCM encryption logic here
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(nonce) != aesgcm.NonceSize() {
		return nil, errors.New("nonce length is invalid")
	}
	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

func main() {
	// Example usage of encrypt_aes_gcm
	key := []byte("examplekey123456") // 16 bytes for AES-128
	nonce := make([]byte, 12)         // GCM standard nonce size
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		panic(err)
	}
	plaintext := []byte("Hello, World!")
	ciphertext, err := encrypt_aes_gcm(plaintext, key, nonce)
	if err != nil {
		panic(err)
	}
	// Output the ciphertext
	println("Ciphertext:", hex.EncodeToString(ciphertext))
}
