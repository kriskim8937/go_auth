package auth_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"authflow/internal/auth"

	"github.com/stretchr/testify/assert"
)

func TestE2E(t *testing.T) {
	//TestAuthorizeEndpoint
	service := auth.NewService()
	handler := auth.NewHandler(service)
	r := setupRouter(handler)

	req, _ := http.NewRequest("GET", "/authorize?client_id=client_id_1&redirect_uri=http://localhost/callback&response_type=code", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusFound, w.Code)
	rawURL := w.Header().Get("Location")
	assert.Contains(t, w.Header().Get("Location"), "code=")
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		fmt.Println("Error parsing URL:", err)
		return
	}

	queryParams := parsedURL.Query()
	code := queryParams.Get("code")

	fmt.Println("Code:", code)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", code)
	data.Set("client_id", "client_id_1")
	data.Set("redirect_uri", "http://localhost/callback")

	req, _ = http.NewRequest("POST", "/token", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "access_token")

	req, _ = http.NewRequest("GET", "/userinfo", nil)
	w = httptest.NewRecorder()
	r.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Body.String(), "dummy_user_info")
}
