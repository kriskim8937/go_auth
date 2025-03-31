package auth

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type Handler struct {
	Service *Service
}

func NewHandler(service *Service) *Handler {
	return &Handler{Service: service}
}

// UserInfo handles user information retrieval based on the access token
func (h *Handler) UserInfo(c *gin.Context) {
	// Extract the access token from the Authorization header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing access token"})
		return
	}

	// Ensure the token follows the "Bearer <token>" format
	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
		return
	}

	accessToken := parts[1]

	// Validate the token
	userInfo, err := h.Service.ValidateAccessToken(accessToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		return
	}

	// Return user information
	c.JSON(http.StatusOK, gin.H{"user": userInfo})
}

func (s *Service) ValidateAccessToken(token string) (string, error) {
	// Simulating token validation (Replace with actual logic, e.g., checking a database)
	validTokens := map[string]string{
		"abcd1234": "user_1",
		"xyz7890":  "user_2",
	}

	user, exists := validTokens[token]
	if !exists {
		return "", errors.New("invalid token")
	}

	return user, nil
}

type AuthorizationRequest struct {
	ClientID     string `form:"client_id" binding:"required"`
	RedirectURI  string `form:"redirect_uri" binding:"required"`
	ResponseType string `form:"response_type" binding:"required"`
	Scope        string `form:"scope"`
	State        string `form:"state"`
}

type TokenRequest struct {
	GrantType   string `form:"grant_type" binding:"required"`
	Code        string `form:"code" binding:"required"`
	ClientID    string `form:"client_id" binding:"required"`
	RedirectURI string `form:"redirect_uri" binding:"required"`
}

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

// Authorize handles the authorization code flow
func (h *Handler) Authorize(c *gin.Context) {
	var request AuthorizationRequest
	if err := c.ShouldBindQuery(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	if !isValidClient(request.ClientID) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid client"})
		return
	}

	// Generate and store authorization code
	code := uuid.New().String()
	h.Service.StoreAuthorizationCode(code, request.ClientID)

	// Redirect user with the code
	redirectURL := request.RedirectURI + "?code=" + code
	if request.State != "" {
		redirectURL += "&state=" + request.State
	}

	c.Redirect(http.StatusFound, redirectURL)
}

func isValidClient(clientID string) bool {
	validClients := []string{"client_id_1", "client_id_2"}
	for _, id := range validClients {
		if id == clientID {
			return true
		}
	}
	return false
}

// Token handles token exchange
func (h *Handler) Token(c *gin.Context) {
	var request TokenRequest
	if err := c.ShouldBind(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	switch request.GrantType {
	case "authorization_code":
		h.handleAuthorizationCodeGrant(c, request)
	case "client_credentials":
		h.handleClientCredentialsGrant(c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
	}
}

func (h *Handler) handleAuthorizationCodeGrant(c *gin.Context, request TokenRequest) {
	if !h.Service.ValidateAndRemoveAuthorizationCode(request.Code, request.ClientID) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired authorization code"})
		return
	}

	// Generate access token
	accessToken := uuid.New().String()
	expiresIn := int64(3600)

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
	})
}

func (h *Handler) handleClientCredentialsGrant(c *gin.Context) {
	clientID := c.PostForm("client_id")
	clientSecret := c.PostForm("client_secret")

	if clientID != "valid-client-id" || clientSecret != "valid-client-secret" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	// Generate access token
	accessToken := uuid.New().String()

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   3600,
	})
}
