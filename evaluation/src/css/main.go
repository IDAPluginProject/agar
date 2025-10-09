package main

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"embed"
	"io/fs"
)

func cspMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// TODO: Disable unsafe-inline for production
		c.Header("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; img-src 'self'; connect-src 'self'; font-src 'self' https://fonts.googleapis.com https://fonts.gstatic.com; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
		c.Next()
	}
}

//go:embed build/client/*
var embeddedFiles embed.FS

func main() {
	r := gin.New()
	r.Use(cspMiddleware())
	r.Use(gin.Recovery())
	r.Use(gin.Logger())
	r.SetTrustedProxies(nil)

	api := r.Group("/api")
	api.POST("/login", HandleLogin)
	api.POST("/register", HandleRegister)
	api.GET("/me", authMiddleware(false), HandleMe)
	api.GET("/views", authMiddleware(false), HandleGetViews)
	api.GET("/profile/:username", authMiddleware(true), HandleGetProfile)
	api.POST("/update_style", authMiddleware(false), HandleStyleColorUpdate)
	api.GET("/vault/unlock/request", authMiddleware(false), HandleUnlockRequest)
	api.POST("/vault/unlock/attempt", authMiddleware(false), HandleUnlockAttempt)
	api.POST("/vault/check", authMiddleware(false), HandleCheckSecret)

	subFS, err := fs.Sub(embeddedFiles, "build/client/assets")
	if err != nil {
		panic(err)
	}
	r.StaticFS("/assets", http.FS(subFS))
	r.NoRoute(func(c *gin.Context) {
		// Serve the index.html file from the embedded files
		indexFile, err := embeddedFiles.ReadFile("build/client/index.html")
		if err != nil {
			c.String(http.StatusInternalServerError, "Error reading index file: %v", err)
			return
		}
		c.Data(http.StatusOK, "text/html; charset=utf-8", indexFile)
	})
	r.Run(":8080")
}
