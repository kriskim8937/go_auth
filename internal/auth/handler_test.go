package auth_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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

	req, _ := http.NewRequest("GET", "/auth/authorize?client_id=client_id_1&redirect_uri=http://localhost/callback&response_type=code", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "code=")
}

func TestTokenEndpoint_AuthorizationCodeGrant_InvalidCode(t *testing.T) {
	service := setupService() // Use Redis-backed service
	handler := auth.NewHandler(service)
	r := setupRouter(handler)

	body := "grant_type=authorization_code&code=invalid_code&client_id=client_id_1&redirect_uri=http://localhost/callback"
	req, _ := http.NewRequest("POST", "/auth/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired authorization code")
}

func TestTokenEndpoint_AuthorizationCodeGrant_ValidCode(t *testing.T) {
	service := setupService() // Use Redis-backed service
	handler := auth.NewHandler(service)
	r := setupRouter(handler)

	// Simulating authorization code issuance
	code := "valid_code"
	service.StoreAuthorizationCode(code, "client_id_1")

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", "client_id_1")
	data.Set("redirect_uri", "http://localhost/callback")

	req, _ := http.NewRequest("POST", "/auth/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "access_token")
}

func TestUserInfo_ValidToken(t *testing.T) {
	service := setupService() // Use Redis-backed service
	handler := auth.NewHandler(service)
	r := setupRouter(handler)

	// Simulating access token issuance
	accessToken := "valid_access_token"
	service.StoreAccessToken(accessToken, "user_1", 3600) // Store token for user_1

	req, _ := http.NewRequest("GET", "/auth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+accessToken)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "user_1")
}

func TestUserInfo_InvalidToken(t *testing.T) {
	service := setupService() // Use Redis-backed service
	handler := auth.NewHandler(service)
	r := setupRouter(handler)

	req, _ := http.NewRequest("GET", "/auth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer invalid_token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired token")
}
