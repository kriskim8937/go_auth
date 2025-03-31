package main

import (
	"authflow/internal/auth"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	authService := auth.NewService()
	authHandler := auth.NewHandler(authService)

	// Define OAuth 2.1 routes
	r.POST("/auth/authorize", authHandler.Authorize)
	r.POST("/auth/token", authHandler.Token)
	r.GET("/auth/userinfo", authHandler.UserInfo)

	r.Run(":8080") // Run the server on port 8080
}
