package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestAuthorize(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.Default()
	service := NewService()
	handler := NewHandler(service)

	router.GET("/auth/authorize", handler.Authorize)

	req, _ := http.NewRequest(http.MethodGet, "/auth/authorize?client_id=client_id_1&redirect_uri=http://localhost/callback&response_type=code", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	if w.Code != http.StatusFound {
		t.Errorf("Expected status %d, got %d", http.StatusFound, w.Code)
	}
}
