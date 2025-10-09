package main

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"jro.sg/tisc/secure-vault/countle"
)

type UnlockAttempt struct {
	B          string              `json:"b"`
	Operations []countle.Operation `json:"operations"`
}

func newOTP() (int, error) {
	for {
		otp, err := rand.Int(rand.Reader, big.NewInt(1e5))
		if err != nil {
			return 0, err
		}
		if len(otp.String()) == 4 && otp.Int64() > 0 {
			return int(otp.Int64()), nil
		}
	}
}

func HandleUnlockAttempt(context *gin.Context) {
	// Get the username from the context
	username := context.GetString("username")

	otp, auth_level, err := getOTP(username)
	if err != nil {
		context.JSON(500, gin.H{"error": err.Error()})
		return
	}

	var attempt UnlockAttempt
	if err := context.BindJSON(&attempt); err != nil {
		context.JSON(400, gin.H{"error": "Invalid request body"})
		return
	}

	if !countle.Validate(attempt.Operations, otp) {
		context.JSON(400, gin.H{"error": "Invalid OTP!"})
		otp, _ := newOTP()
		setOTP(username, otp, 0)
		return
	}

	auth_level += 1

	if auth_level > 1 {
		secret, err := getSecret(username)
		if err != nil {
			context.JSON(500, gin.H{"error": err.Error()})
			return
		}

		context.JSON(200, gin.H{
			"message": "Unlock successful, secret is " + secret,
		})
		return
	}
	otp, err = newOTP()
	if err != nil {
		context.JSON(500, gin.H{"error": err.Error()})
		return
	}
	setOTP(username, otp, auth_level)
	context.JSON(200, gin.H{
		"message": "Correct OTP. However, as you are accessing sensitive information, a second OTP has been sent to your device. Please refresh the page to enter the new OTP.",
	})
}

func HandleUnlockRequest(context *gin.Context) {
	username := context.GetString("username")

	otp, auth_level, err := getOTP(username)
	if err == errorInvalidOTP {
		auth_level = 0
		otp, err = newOTP()
		if err != nil {
			context.JSON(500, gin.H{"error": err.Error()})
			return
		}
		if err := setOTP(username, otp, auth_level); err != nil {
			context.JSON(500, gin.H{"error": err.Error()})
			return
		}
	} else if err != nil {
		context.JSON(500, gin.H{"error": err.Error()})
		return
	}
	fmt.Println("OTP:", otp)
	context.JSON(200, gin.H{
		"auth_level": auth_level,
	})
}

func HandleCheckSecret(context *gin.Context) {
	// Get the username from the context
	username := context.GetString("username")

	otp, _, err := getOTP(username)
	if err != nil {
		context.JSON(500, gin.H{"error": err.Error()})
		return
	}

	adminBotAddress := os.Getenv("ADMIN_BOT_ADDRESS")
	if adminBotAddress == "" {
		context.JSON(500, gin.H{"error": "Admin bot address not set"})
		return
	}

	conn, err := net.Dial("tcp", adminBotAddress)
	if err != nil {
		context.JSON(500, gin.H{"error": "Failed to connect to admin bot"})
		return
	}
	defer conn.Close()

	conn.Read(make([]byte, 1024))
	token, err := genToken(username)
	if err != nil {
		context.JSON(500, gin.H{"error": "Failed to generate token"})
		return
	}
	conn.Write([]byte(token))
	conn.Read(make([]byte, 1024))

	conn.Write([]byte(strconv.Itoa(otp)))
	res := make([]byte, 1024)
	_, err = conn.Read(res)
	if err != nil {
		context.JSON(500, gin.H{"error": "Failed to read response from admin bot"})
		return
	}
	context.JSON(200, gin.H{
		"message": strings.ReplaceAll(string(res), "\x00", ""),
	})
}
