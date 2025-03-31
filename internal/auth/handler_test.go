package auth_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"authflow/internal/auth"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func setupRouter(handler *auth.Handler) *gin.Engine {
	r := gin.Default()
	r.GET("/authorize", handler.Authorize)
	r.POST("/token", handler.Token)
	r.GET("/userinfo", handler.UserInfo)
	return r
}

func TestAuthorizeEndpoint(t *testing.T) {
	service := auth.NewService()
	handler := auth.NewHandler(service)
	r := setupRouter(handler)

	req, _ := http.NewRequest("GET", "/authorize?client_id=client_id_1&redirect_uri=http://localhost/callback&response_type=code", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	assert.Contains(t, w.Header().Get("Location"), "code=")
}

// func TestTokenEndpoint_InvalidGrantType(t *testing.T) {
// 	service := auth.NewService()
// 	handler := auth.NewHandler(service)
// 	r := setupRouter(handler)

// 	req, _ := http.NewRequest("POST", "/token", nil)
// 	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
// 	w := httptest.NewRecorder()
// 	r.ServeHTTP(w, req)

// 	assert.Equal(t, http.StatusBadRequest, w.Code)
// 	assert.Contains(t, w.Body.String(), "unsupported_grant_type")
// }

func TestTokenEndpoint_AuthorizationCodeGrant_InvalidCode(t *testing.T) {
	service := auth.NewService()
	handler := auth.NewHandler(service)
	r := setupRouter(handler)

	body := "grant_type=authorization_code&code=invalid_code&client_id=client_id_1&redirect_uri=http://localhost/callback"
	req, _ := http.NewRequest("POST", "/token", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "Invalid or expired authorization code")
}

func TestTokenEndpoint_AuthorizationCodeGrant_ValidCode(t *testing.T) {
	service := auth.NewService()
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

	req, _ := http.NewRequest("POST", "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "access_token")
}

func TestUserInfoEndpoint(t *testing.T) {
	service := auth.NewService()
	handler := auth.NewHandler(service)
	r := setupRouter(handler)

	req, _ := http.NewRequest("GET", "/userinfo", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "dummy_user_info")
}
