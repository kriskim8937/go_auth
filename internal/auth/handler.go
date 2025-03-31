package auth

// 1. Handler
// Responsibility: Handles HTTP requests and responses. It acts as the entry point for incoming API calls.

// Role: The Handler parses requests, invokes appropriate methods on the Service, and sends back responses.

// Example: In your handler.go, the Authorize, Token, and UserInfo methods receive HTTP requests, call the corresponding service methods, and return JSON responses.

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Handler struct {
	Service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{Service: service}
}

// Token handles the token exchange for the authorization code flow
func (h *Handler) Token(c *gin.Context) {
	// Implement token exchange logic here
	c.JSON(http.StatusOK, gin.H{"access_token": "dummy_access_token"})
}

// UserInfo handles user information retrieval based on the access token
func (h *Handler) UserInfo(c *gin.Context) {
	// Validate the access token and return user info
	c.JSON(http.StatusOK, gin.H{"user": "dummy_user_info"})
}

type AuthorizationRequest struct {
	ClientID     string `form:"client_id" binding:"required"`
	RedirectURI  string `form:"redirect_uri" binding:"required"`
	ResponseType string `form:"response_type" binding:"required"`
	Scope        string `form:"scope"`
	State        string `form:"state"`
}

var authorizationCodes = make(map[string]string) // In-memory store for demo purposes

// Authorize handles the authorization code flow
func (h *Handler) Authorize(c *gin.Context) {
	var request AuthorizationRequest
	if err := c.ShouldBindQuery(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Step 1: Validate the client (this should check against a database in production)
	if !isValidClient(request.ClientID) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid client"})
		return
	}

	// Step 2: Generate an authorization code
	code := uuid.New().String()
	authorizationCodes[code] = request.ClientID // Store code with associated client ID

	// Step 3: Redirect the user with the authorization code
	redirectURL := request.RedirectURI + "?code=" + code
	if request.State != "" {
		redirectURL += "&state=" + request.State
	}

	c.Redirect(http.StatusFound, redirectURL)
}

// isValidClient checks if the client ID is valid
func isValidClient(clientID string) bool {
	// Placeholder validation; replace with real validation against a database
	validClients := []string{"client_id_1", "client_id_2"}
	for _, id := range validClients {
		if id == clientID {
			return true
		}
	}
	return false
}
