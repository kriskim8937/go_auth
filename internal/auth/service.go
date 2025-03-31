package auth

import (
	"sync"
)

// Service provides methods for handling OAuth logic
type Service struct {
	mu                 sync.Mutex
	authorizationCodes map[string]string
}

// NewService creates a new authentication service
func NewService() *Service {
	return &Service{
		authorizationCodes: make(map[string]string),
	}
}

// StoreAuthorizationCode saves an authorization code for a client
func (s *Service) StoreAuthorizationCode(code, clientID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.authorizationCodes[code] = clientID
}

// ValidateAndRemoveAuthorizationCode checks and removes an authorization code
func (s *Service) ValidateAndRemoveAuthorizationCode(code, clientID string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	storedClientID, exists := s.authorizationCodes[code]
	if !exists || storedClientID != clientID {
		return false
	}
	delete(s.authorizationCodes, code) // Remove after successful validation
	return true
}
