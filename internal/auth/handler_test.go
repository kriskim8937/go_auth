package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"authflow/internal/auth"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func setupRouter(handler *auth.Handler) *gin.Engine {
	r := gin.Default()
	r.GET("/auth/authorize", handler.Authorize)
	r.POST("/auth/token", handler.Token)
	r.GET("/auth/userinfo", handler.UserInfo)
	return r
}

func setupService() *auth.Service {
	// Initialize Redis client for testing
	rdb := redis.NewClient(&redis.Options{
		Addr: "redis:6379", // Adjust if necessary
		DB:   0,            // Use default DB
	})
	return auth.NewService(rdb)
}

func TestAuthorizeEndpoint(t *testing.T) {
	service := setupService() // Use Redis-backed service
	handler := auth.NewHandler(service)
	r := setupRouter(handler)

	// Generate a valid PKCE code verifier and challenge (client would do this)
	codeVerifier := "somerandomstring_verifier_1234567890abcdefghijklmnopqrstuvwxyz"
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// Mock user session (since authorize now requires authenticated user)
	req, _ := http.NewRequest(
		"GET",
		"/auth/authorize?client_id=client_id_1"+
			"&redirect_uri=http://localhost/callback"+
			"&response_type=code"+
			"&code_challenge="+codeChallenge+
			"&code_challenge_method=S256",
		nil,
	)

	// Simulate authenticated user (if your middleware requires it)
	req = mockUserSession(req, "user123")

	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	location := w.Header().Get("Location")
	assert.Contains(t, location, "code=")
	assert.Contains(t, location, "http://localhost/callback")
}

// Helper to mock authenticated user session
func mockUserSession(r *http.Request, userID string) *http.Request {
	ctx := context.WithValue(r.Context(), "user_id", userID) // Adjust based on your auth system
	return r.WithContext(ctx)
}

// func TestTokenEndpoint_AuthorizationCodeGrant_InvalidCode(t *testing.T) {
// 	service := setupService() // Use Redis-backed service
// 	handler := auth.NewHandler(service)
// 	r := setupRouter(handler)

// 	// Create form data with all required fields including PKCE code_verifier
// 	form := url.Values{}
// 	form.Set("grant_type", "authorization_code")
// 	form.Set("code", "invalid_code")
// 	form.Set("client_id", "client_id_1")
// 	form.Set("redirect_uri", "http://localhost/callback")
// 	form.Set("code_verifier", "somerandomstring_verifier_1234567890abcdefghijklmnopqrstuvwxyz")

// 	req, _ := http.NewRequest("POST", "/auth/token", strings.NewReader(form.Encode()))
// 	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

// 	// If your endpoint requires basic auth for client authentication
// 	req.SetBasicAuth("client_id_1", "client_secret_1")

// 	w := httptest.NewRecorder()
// 	r.ServeHTTP(w, req)

// 	// Verify response
// 	assert.Equal(t, http.StatusUnauthorized, w.Code)

// 	var response map[string]string
// 	err := json.Unmarshal(w.Body.Bytes(), &response)
// 	assert.NoError(t, err)
// 	assert.Equal(t, "Invalid or expired authorization code", response["error"])
// }

// func TestTokenEndpoint_AuthorizationCodeGrant_ValidCode(t *testing.T) {
// 	service := setupService()
// 	handler := auth.NewHandler(service)
// 	r := setupRouter(handler)

// 	// Generate PKCE verifier and challenge
// 	codeVerifier := "somerandomstring_verifier_1234567890abcdefghijklmnopqrstuvwxyz"
// 	hash := sha256.Sum256([]byte(codeVerifier))
// 	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

// 	// Store authorization code with PKCE challenge and user context
// 	code := "valid_code"
// 	err := service.StoreAuthorizationCode(code, "client_id_1", codeChallenge)
// 	assert.NoError(t, err)

// 	// Prepare token request with all required fields
// 	data := url.Values{}
// 	data.Set("grant_type", "authorization_code")
// 	data.Set("code", code)
// 	data.Set("client_id", "client_id_1")
// 	data.Set("redirect_uri", "http://localhost/callback")
// 	data.Set("code_verifier", codeVerifier) // PKCE verifier

// 	req, _ := http.NewRequest("POST", "/auth/token", strings.NewReader(data.Encode()))
// 	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

// 	// Add client authentication if required
// 	req.SetBasicAuth("client_id_1", "client_secret_1")

// 	w := httptest.NewRecorder()
// 	r.ServeHTTP(w, req)

// 	// Verify response
// 	assert.Equal(t, http.StatusOK, w.Code)

// 	var response map[string]interface{}
// 	err = json.Unmarshal(w.Body.Bytes(), &response)
// 	assert.NoError(t, err)

// 	assert.NotEmpty(t, response["access_token"])
// 	assert.Equal(t, "Bearer", response["token_type"])
// 	assert.IsType(t, float64(0), response["expires_in"])
// }

// func TestUserInfo_ValidToken(t *testing.T) {
// 	service := setupService()
// 	handler := auth.NewHandler(service)
// 	r := setupRouter(handler)

// 	// Store access token with metadata
// 	accessToken := "valid_access_token"
// 	err := service.StoreAccessToken(accessToken, "client_id_1", 3600)
// 	assert.NoError(t, err)

// 	req, _ := http.NewRequest("GET", "/auth/userinfo", nil)
// 	req.Header.Set("Authorization", "Bearer "+accessToken)
// 	w := httptest.NewRecorder()
// 	r.ServeHTTP(w, req)

// 	// Verify response
// 	assert.Equal(t, http.StatusOK, w.Code)

// 	var response map[string]interface{}
// 	err = json.Unmarshal(w.Body.Bytes(), &response)
// 	assert.NoError(t, err)

// 	userInfo, exists := response["user"]
// 	assert.True(t, exists)

// 	userMap, ok := userInfo.(map[string]interface{})
// 	assert.True(t, ok)
// 	fmt.Println(userMap)
// 	assert.Equal(t, "client_id_1", userMap["client_id"]) // Adjust based on your user info structure
// }

func TestUserInfo_InvalidToken(t *testing.T) {
	service := setupService()
	handler := auth.NewHandler(service)
	r := setupRouter(handler)

	testCases := []struct {
		name          string
		token         string
		expectedError string
	}{
		{
			name:          "malformed token",
			token:         "malformed_token",
			expectedError: "Invalid or expired token",
		},
		{
			name:          "missing token",
			token:         "",
			expectedError: "Missing access token",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req, _ := http.NewRequest("GET", "/auth/userinfo", nil)
			if tc.token != "" {
				req.Header.Set("Authorization", "Bearer "+tc.token)
			}

			w := httptest.NewRecorder()
			r.ServeHTTP(w, req)

			assert.Equal(t, http.StatusUnauthorized, w.Code)

			var response map[string]string
			err := json.Unmarshal(w.Body.Bytes(), &response)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedError, response["error"])
		})
	}
}
