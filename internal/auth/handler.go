package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
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
	userInfo, err := h.Service.ValidateAccessToken(accessToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"user": userInfo})
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
	Code         string `form:"code" binding:"required"`
	ClientID     string `form:"client_id" binding:"required"`
	RedirectURI  string `form:"redirect_uri" binding:"required"`
	CodeVerifier string `form:"code_verifier" binding:"required"` // PKCE: Client sends original secret
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

	// Validate PKCE method (only S256 is secure)
	if request.CodeChallengeMethod != "S256" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_challenge_method"})
		return
	}

	if !isValidClient(request.ClientID) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid client"})
		return
	}

	// Store code_challenge (linked to the auth code)
	code := uuid.New().String()
	h.Service.StoreAuthorizationCode(code, request.ClientID, request.CodeChallenge) // Updated function

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
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
	}
}

func (h *Handler) handleAuthorizationCodeGrant(c *gin.Context, request TokenRequest) {
	// Retrieve stored code_challenge for this auth code
	codeChallenge, isValid := h.Service.ValidateAndRemoveAuthorizationCode(request.Code, request.ClientID)
	if !isValid {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired authorization code"})
		return
	}

	// Verify PKCE: Compare code_verifier vs. stored code_challenge
	if !VerifyPKCE(codeChallenge, request.CodeVerifier) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_code_verifier"})
		return
	}

	// Generate and return tokens (same as before)
	accessToken := GenerateSecureToken(32)
	expiresIn := int64(3600)
	h.Service.StoreAccessToken(accessToken, request.ClientID, expiresIn)

	c.JSON(http.StatusOK, TokenResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresIn:   expiresIn,
	})
}

func GenerateSecureToken(length int) string {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return base64.URLEncoding.EncodeToString(b)
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
