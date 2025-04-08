package auth

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
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

func (h *Handler) UserInfo(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Missing access token"})
		return
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token format"})
		return
	}

	accessToken := parts[1]
	tokenInfo, err := h.Service.ValidateAccessToken(accessToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"sub":       tokenInfo["user_id"],
		"client_id": tokenInfo["client_id"],
		"name":      "Test User",
		"email":     "test@example.com",
	})
}

type AuthorizationRequest struct {
	ClientID            string `form:"client_id" binding:"required"`
	RedirectURI         string `form:"redirect_uri" binding:"required"`
	ResponseType        string `form:"response_type" binding:"required"`
	Scope               string `form:"scope"`
	State               string `form:"state"`
	CodeChallenge       string `form:"code_challenge" binding:"required"`        // PKCE: Client sends hash
	CodeChallengeMethod string `form:"code_challenge_method" binding:"required"` // "S256" or "plain"
}

type TokenRequest struct {
	GrantType    string `form:"grant_type" binding:"required"`
	Code         string `form:"code"` // Not required for refresh_token
	ClientID     string `form:"client_id" binding:"required"`
	RedirectURI  string `form:"redirect_uri"`  // Not required for refresh_token
	CodeVerifier string `form:"code_verifier"` // Not required for refresh_token
	RefreshToken string `form:"refresh_token"` // Required for refresh_token
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
}

// Authorize handles the authorization code flow
func (h *Handler) Authorize(c *gin.Context) {
	var request AuthorizationRequest
	if err := c.ShouldBindQuery(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Simulate authenticated user session
	userID, ok := c.Request.Context().Value("user_id").(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
		return
	}
	c.Request = c.Request.WithContext(context.WithValue(c.Request.Context(), "user_id", userID))

	// Validate PKCE method (only S256 is secure)
	if request.CodeChallengeMethod != "S256" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_challenge_method"})
		return
	}

	if !isValidClient(request.ClientID) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid client"})
		return
	}

	// Store code_challenge and userID (linked to the auth code)
	code := uuid.New().String()
	if err := h.Service.StoreAuthorizationCode(code, request.ClientID, request.CodeChallenge, userID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store authorization code"})
		return
	}

	// Redirect with code
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
	case "refresh_token":
		h.handleRefreshTokenGrant(c)
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
	}
}

func (h *Handler) handleAuthorizationCodeGrant(c *gin.Context, request TokenRequest) {
	// Validate and remove auth code - now returns userID too
	codeChallenge, userID, isValid := h.Service.ValidateAndRemoveAuthorizationCode(request.Code, request.ClientID)
	if !isValid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired authorization code"})
		return
	}

	// Verify PKCE
	if !VerifyPKCE(codeChallenge, request.CodeVerifier) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_code_verifier"})
		return
	}

	// Generate tokens
	accessToken := GenerateSecureToken(32)
	refreshToken := GenerateSecureToken(32)
	expiresIn := int64(3600)

	// Store tokens with userID
	if err := h.Service.StoreAccessToken(accessToken, request.ClientID, userID, expiresIn); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store access token"})
		return
	}

	if err := h.Service.StoreRefreshToken(refreshToken, request.ClientID, userID, 24*3600); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store refresh token"})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: refreshToken,
	})
}

func (h *Handler) handleRefreshTokenGrant(c *gin.Context) {
	fmt.Println("Refresh token request received")
	body, _ := io.ReadAll(c.Request.Body)
	fmt.Printf("Request body: %s\n", string(body))
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))
	type refreshRequest struct {
		GrantType    string `form:"grant_type" binding:"required"`
		RefreshToken string `form:"refresh_token" binding:"required"`
		ClientID     string `form:"client_id" binding:"required"`
	}

	var req refreshRequest
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request"})
		return
	}

	userID, isValid := h.Service.ValidateRefreshToken(req.RefreshToken, req.ClientID)
	if !isValid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_grant"})
		return
	}

	// Invalidate old token
	if err := h.Service.DeleteRefreshToken(req.RefreshToken); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Generate new tokens
	accessToken := GenerateSecureToken(32)
	newRefreshToken := GenerateSecureToken(32)
	expiresIn := int64(3600) // 1 hour

	// Store new tokens
	if err := h.Service.StoreAccessToken(accessToken, req.ClientID, userID, expiresIn); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}
	if err := h.Service.StoreRefreshToken(newRefreshToken, req.ClientID, userID, 24*3600); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken:  accessToken,
		TokenType:    "Bearer",
		ExpiresIn:    expiresIn,
		RefreshToken: newRefreshToken,
	})
}

func (s *Service) DeleteRefreshToken(token string) error {
	ctx := context.Background()
	return s.RedisClient.Del(ctx, "refresh_token:"+token).Err()
}

func GenerateSecureToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

func VerifyPKCE(codeChallenge, codeVerifier string) bool {
	// Default: S256 (recommended)
	hash := sha256.Sum256([]byte(codeVerifier))
	encoded := base64.RawURLEncoding.EncodeToString(hash[:])
	return encoded == codeChallenge
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
