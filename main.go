package main

import (
	"authflow/internal/auth"
	"log"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
)

func main() {
	r := gin.Default()

	redisAddr := "redis:6379"
	rdb := redis.NewClient(&redis.Options{
		Addr: redisAddr, // Use "redis:6379" for Docker setup
		DB:   0,         // Default database
	}) // Adjust this if your Redis service runs on a different address
	authService := auth.NewService(rdb) // Pass Redis address to the service
	authHandler := auth.NewHandler(authService)

	// Define OAuth 2.1 routes
	r.POST("/auth/authorize", authHandler.Authorize)
	r.POST("/auth/token", authHandler.Token)
	r.GET("/auth/userinfo", authHandler.UserInfo)

	log.Println("Server is running on port 8080...")

	if err := r.Run(":8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
