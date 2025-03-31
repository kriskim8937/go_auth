// package main

// import (
// 	"authflow/internal/auth"

// 	"github.com/gin-gonic/gin"
// )

// func main() {
// 	r := gin.Default()

// 	authService := auth.NewService()
// 	authHandler := auth.NewHandler(authService)

// 	// Define OAuth 2.1 routes
// 	r.POST("/auth/authorize", authHandler.Authorize)
// 	r.POST("/auth/token", authHandler.Token)
// 	r.GET("/auth/userinfo", authHandler.UserInfo)

// 	r.Run(":8080") // Run the server on port 8080
// }

package main

import (
	"authflow/internal/auth"
	"log"

	"github.com/gin-gonic/gin"
)

func main() {
	r := gin.Default()

	authService := auth.NewService()
	authHandler := auth.NewHandler(authService)

	// Define OAuth 2.1 routes
	r.GET("/auth/authorize", authHandler.Authorize)
	r.POST("/auth/token", authHandler.Token)

	log.Println("Server is running on port 8080...")

	if err := r.Run(":8080"); err != nil {
		log.Fatal("Failed to start server:", err)
	}
}
