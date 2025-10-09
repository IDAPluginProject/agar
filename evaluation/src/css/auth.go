package main

import (
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func HandleLogin(context *gin.Context) {
	// Get the username and password from the request
	username := context.PostForm("username")
	password := context.PostForm("password")

	success, err := loginUser(username, password)
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !success {
		context.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
		return
	}
	token, err := genToken(username)
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	context.JSON(http.StatusOK, gin.H{"message": "Login successful", "token": token})
}

func HandleRegister(context *gin.Context) {
	// Get the username and password from the request
	username := context.PostForm("username")
	password := context.PostForm("password")
	secret := context.PostForm("secret")
	bio := context.PostForm("bio")

	// Restrict username to alphanumeric only
	for _, c := range username {
		if !(('a' <= c && c <= 'z') || ('A' <= c && c <= 'Z') || ('0' <= c && c <= '9')) {
			context.JSON(http.StatusBadRequest, gin.H{"error": "Username must be alphanumeric"})
			return
		}
	}

	if len(username) < 5 {
		context.JSON(http.StatusBadRequest, gin.H{"error": "Username must be at least 5 characters long"})
		return
	}

	if len(password) < 8 || len(password) > 64 {
		context.JSON(http.StatusBadRequest, gin.H{"error": "Password must be between 8 and 64 characters long"})
		return
	}

	err := createUser(username, password, bio, secret)
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	err = createUser("admin_"+username, randomPassword(), "Admin account for "+username, os.Getenv("FLAG"))
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create admin account: " + err.Error()})
		return
	}

	token, err := genToken(username)
	if err != nil {
		context.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	context.JSON(http.StatusOK, gin.H{"message": "User created successfully", "token": token})
}

func authMiddleware(allowAnonymous bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		token := c.GetHeader("Authorization")
		if token == "" {
			if allowAnonymous {
				c.Set("username", "anonymous")
				c.Next()
				return
			}
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			c.Abort()
			return
		}
		username, err := validateToken(token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}
		c.Set("username", username)
		c.Next()
	}
}
