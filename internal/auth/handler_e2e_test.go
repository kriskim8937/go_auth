package auth_test

import (
	"authflow/internal/auth"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

func TestE2E(t *testing.T) {
	service := setupService() // Use Redis-backed service
	handler := auth.NewHandler(service)
	r := setupRouter(handler)

	// Step 1: Authorize
	req, _ := http.NewRequest("GET", "/auth/authorize?client_id=client_id_1&redirect_uri=http://localhost/callback&response_type=code", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	rawURL := w.Header().Get("Location")
	assert.Contains(t, rawURL, "code=")

	// Parse the URL to extract the authorization code
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("Error parsing URL: %v", err)
	}

	queryParams := parsedURL.Query()
	code := queryParams.Get("code")
	assert.NotEmpty(t, code, "Authorization code should not be empty")

	// Step 2: Exchange authorization code for access token
	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", "client_id_1")
	data.Set("redirect_uri", "http://localhost/callback")

	req, _ = http.NewRequest("POST", "/auth/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	// Step 3: Decode the access token from the response
	var tokenResponse TokenResponse
	err = json.Unmarshal(w.Body.Bytes(), &tokenResponse)
	if err != nil {
		t.Fatalf("Error decoding token response: %v", err)
	}
	assert.NotEmpty(t, tokenResponse.AccessToken, "Access token should not be empty")

	// Step 4: Use the access token to get user info
	req, _ = http.NewRequest("GET", "/auth/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "client_id_1") // Adjust this based on the actual expected user info response
}
