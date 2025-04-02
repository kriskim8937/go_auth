package auth_test

import (
	"authflow/internal/auth"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int64  `json:"expires_in"`
}

func TestE2EOAuthFlowWithPKCE(t *testing.T) {
	service := setupService()
	handler := auth.NewHandler(service)
	r := setupRouter(handler)

	// Generate PKCE code verifier and challenge
	codeVerifier := "somerandomstring_verifier_1234567890abcdefghijklmnopqrstuvwxyz"
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(hash[:])

	// --- Step 1: Authorization Request ---
	authReq, _ := http.NewRequest(
		"GET",
		"/auth/authorize?"+url.Values{
			"client_id":             {"client_id_1"},
			"redirect_uri":          {"http://localhost/callback"},
			"response_type":         {"code"},
			"code_challenge":        {codeChallenge},
			"code_challenge_method": {"S256"},
			"state":                 {"test_state"},
		}.Encode(),
		nil,
	)

	// Simulate authenticated user session
	authReq = authReq.WithContext(
		context.WithValue(authReq.Context(), "user_id", "test_user"),
	)

	authRec := httptest.NewRecorder()
	r.ServeHTTP(authRec, authReq)

	assert.Equal(t, http.StatusFound, authRec.Code, "Authorization should redirect")
	location := authRec.Header().Get("Location")
	assert.Contains(t, location, "http://localhost/callback", "Should redirect to callback URI")
	assert.Contains(t, location, "code=", "Should contain authorization code")
	assert.Contains(t, location, "state=test_state", "Should return state parameter")

	// Extract authorization code
	parsedURL, err := url.Parse(location)
	require.NoError(t, err, "Should parse redirect URL correctly")
	code := parsedURL.Query().Get("code")
	assert.NotEmpty(t, code, "Authorization code should not be empty")

	// --- Step 2: Token Exchange ---
	tokenReqBody := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {"client_id_1"},
		"redirect_uri":  {"http://localhost/callback"},
		"code_verifier": {codeVerifier}, // PKCE verifier
	}

	tokenReq, _ := http.NewRequest(
		"POST",
		"/auth/token",
		strings.NewReader(tokenReqBody.Encode()),
	)
	tokenReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Add client authentication if required
	tokenReq.SetBasicAuth("client_id_1", "client_secret_1")

	tokenRec := httptest.NewRecorder()
	r.ServeHTTP(tokenRec, tokenReq)

	assert.Equal(t, http.StatusOK, tokenRec.Code, "Token request should succeed")

	var tokenResponse TokenResponse
	err = json.Unmarshal(tokenRec.Body.Bytes(), &tokenResponse)
	require.NoError(t, err, "Should decode token response correctly")

	assert.NotEmpty(t, tokenResponse.AccessToken, "Access token should be provided")
	assert.Equal(t, "Bearer", tokenResponse.TokenType, "Token type should be Bearer")
	assert.Greater(t, tokenResponse.ExpiresIn, int64(0), "ExpiresIn should be positive")

	// --- Step 3: UserInfo Request ---
	userInfoReq, _ := http.NewRequest("GET", "/auth/userinfo", nil)
	userInfoReq.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)

	userInfoRec := httptest.NewRecorder()
	r.ServeHTTP(userInfoRec, userInfoReq)

	assert.Equal(t, http.StatusOK, userInfoRec.Code, "UserInfo request should succeed")

	var userInfo map[string]map[string]interface{}
	err = json.Unmarshal(userInfoRec.Body.Bytes(), &userInfo)
	require.NoError(t, err, "Should decode user info correctly")
	fmt.Println(userInfo)
	assert.Equal(t, "client_id_1", userInfo["user"]["client_id"], "Should include client ID")
}
