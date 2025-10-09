package main

import (
	"crypto/aes"
	"crypto/cipher"
	cr "crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/rand"
	"os"
)

func generateKey() [16]byte {
	flag := os.Getenv("FLAG")
	if flag == "" {
		panic("FLAG environment variable is not set")
	}
	h := sha1.New()
	hash := h.Sum([]byte(flag))
	seed := binary.LittleEndian.Uint64(hash[:8])
	rng := rand.New(rand.NewSource(int64(seed)))
	for range 0x100 {
		rng.Int63() // Consume some random numbers to ensure the generator is well seeded
	}
	out := [16]byte{}
	for i := 0; i < 16; i++ {
		out[i] = byte(rng.Int63() & 0xff)
	}
	return out
}

var key = generateKey()

func encrypt(data []byte) ([]byte, error) {
	aesBlock, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := cr.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, data, nil)
	return append(nonce, ciphertext...), nil
}

func decrypt(data []byte) ([]byte, error) {
	aesBlock, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(aesBlock)
	if err != nil {
		return nil, err
	}
	if len(data) < gcm.NonceSize() {
		return nil, errors.New("token must be of form <12 byte nonce><GCM encrypted username>")
	}
	nonce, ciphertext := data[:gcm.NonceSize()], data[gcm.NonceSize():]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}
	return plaintext, nil
}

func genToken(username string) (string, error) {
	data := []byte(username)
	encryptedData, err := encrypt(data)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(encryptedData), nil
}

func validateToken(token string) (string, error) {
	data, err := hex.DecodeString(token)
	if err != nil {
		return "", err
	}
	decryptedData, err := decrypt(data)
	if err != nil {
		return "", err
	}
	return string(decryptedData), nil
}

func randomPassword() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/"
	length := 16
	password := make([]byte, length)
	for i := range password {
		password[i] = charset[rand.Intn(len(charset))]
	}
	return string(password)
}
