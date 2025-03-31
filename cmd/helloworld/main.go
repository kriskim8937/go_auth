package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func main() {
	// Load environment variables
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found")
	}

	r := gin.Default()

	// OAuth Endpoints
	r.GET("/auth", authHandler)
	r.POST("/token", tokenHandler)
	r.GET("/userinfo", userInfoHandler)

	// Start server
	log.Println("Starting AuthFlow server on :8080")
	r.Run(":8080")
}

// authHandler handles user authorization requests
func authHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Authorization Endpoint"})
}

// tokenHandler issues OAuth tokens
func tokenHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "Token Endpoint"})
}

// userInfoHandler provides user information
func userInfoHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"message": "User Info Endpoint"})
}
