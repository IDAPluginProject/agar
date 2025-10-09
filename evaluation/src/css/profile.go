package main

import "github.com/gin-gonic/gin"

func HandleMe(context *gin.Context) {
	// get the username from context
	username, exists := context.Get("username")
	if !exists {
		context.JSON(400, gin.H{"error": "Username not found in context"})
		return
	}

	// Convert username to string
	usernameStr, ok := username.(string)
	if !ok || usernameStr == "" {
		context.JSON(400, gin.H{"error": "Invalid username"})
		return
	}

	// Retrieve user profile information
	profile, err := getUserProfile(usernameStr)
	if err != nil {
		context.JSON(500, gin.H{"error": err.Error()})
		return
	}

	context.JSON(200, gin.H{"profile": profile})
}

func HandleGetProfile(context *gin.Context) {
	// Get the username from the URL parameter
	username := context.Param("username")
	if username == "" {
		context.JSON(400, gin.H{"error": "Username is required"})
		return
	}

	viewer, exists := context.Get("username")
	if !exists {
		viewer = "anonymous"
	}

	// Retrieve user profile information
	profile, err := getUserProfile(username)
	if err != nil {
		context.JSON(500, gin.H{"error": err.Error()})
		return
	}

	err = addView(username, viewer.(string))
	if err != nil {
		context.JSON(500, gin.H{"error": err.Error()})
		return
	}

	context.JSON(200, gin.H{"profile": profile})
}

func HandleGetViews(context *gin.Context) {
	username := context.GetString("username")

	// Retrieve user views
	views, err := getUserViews(username)
	if err != nil {
		context.JSON(500, gin.H{"error": err.Error()})
		return
	}

	context.JSON(200, gin.H{"views": views})
}

func HandleStyleColorUpdate(context *gin.Context) {
	// Get the username from the context
	usernameStr := context.GetString("username")
	if usernameStr == "" {
		context.JSON(400, gin.H{"error": "Username not found in context"})
		return
	}

	color := context.PostForm("style_color")
	if color == "" {
		context.JSON(400, gin.H{"error": "Color is required"})
		return
	}

	err := updateStyleColor(usernameStr, color)
	if err != nil {
		context.JSON(500, gin.H{"error": err.Error()})
		return
	}

	context.JSON(200, gin.H{"message": "Style color updated successfully"})
}
