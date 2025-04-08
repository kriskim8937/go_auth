package auth

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// Service provides methods for handling OAuth logic
type Service struct {
	RedisClient *redis.Client
}

// NewService initializes the service with a Redis client
func NewService(redisClient *redis.Client) *Service {
	return &Service{RedisClient: redisClient}
}

// PKCE-related constants
const (
	PKCEChallengeMethodS256 = "S256"
	AuthCodeTTL             = 10 * time.Minute
)

// StoreAuthorizationCode stores an authorization code, its PKCE code_challenge, and userID in Redis
func (s *Service) StoreAuthorizationCode(code, clientID, codeChallenge, userID string) error {
	ctx := context.Background()
	data := map[string]interface{}{
		"client_id":      clientID,
		"code_challenge": codeChallenge,
		"user_id":        userID,
	}

	err := s.RedisClient.HSet(ctx, "auth_code:"+code, data).Err()
	if err != nil {
		return fmt.Errorf("failed to store authorization code: %w", err)
	}
	return s.RedisClient.Expire(ctx, "auth_code:"+code, AuthCodeTTL).Err()
}

// ValidateAndRemoveAuthorizationCode validates the code and returns the stored code_challenge
func (s *Service) ValidateAndRemoveAuthorizationCode(code, clientID string) (string, string, bool) {
	ctx := context.Background()
	key := "auth_code:" + code

	// Get all fields from the hash
	result, err := s.RedisClient.HGetAll(ctx, key).Result()
	if err != nil || result["client_id"] != clientID {
		return "", "", false
	}

	// Get userID before deleting
	userID := result["user_id"]
	challenge := result["code_challenge"]

	// Delete the code after validation
	s.RedisClient.Del(ctx, key)
	return challenge, userID, true
}

// VerifyPKCE validates a code_verifier against a code_challenge
func (s *Service) VerifyPKCE(codeChallenge, codeVerifier string) bool {
	if codeChallenge == "" || codeVerifier == "" {
		return false
	}

	hash := sha256.Sum256([]byte(codeVerifier))
	calculatedChallenge := base64.RawURLEncoding.EncodeToString(hash[:])
	return calculatedChallenge == codeChallenge
}

// StoreAccessToken saves an access token with metadata
func (s *Service) StoreAccessToken(token, clientID, userID string, expiresIn int64) error {
	ctx := context.Background()
	data := map[string]interface{}{
		"client_id": clientID,
		"user_id":   userID,
	}

	err := s.RedisClient.HSet(ctx, "access_token:"+token, data).Err()
	if err != nil {
		return fmt.Errorf("failed to store access token: %w", err)
	}
	return s.RedisClient.Expire(ctx, "access_token:"+token, time.Duration(expiresIn)*time.Second).Err()
}

// ValidateAccessToken checks if an access token is valid and returns user info
func (s *Service) ValidateAccessToken(token string) (map[string]string, error) {
	ctx := context.Background()
	result, err := s.RedisClient.HGetAll(ctx, "access_token:"+token).Result()
	if err != nil || len(result) == 0 {
		return nil, errors.New("invalid or expired token")
	}
	return result, nil
}

// StoreRefreshToken stores a refresh token with a longer expiry
// In your service, make sure StoreRefreshToken includes expiration:
func (s *Service) StoreRefreshToken(token, clientID, userID string, expiresIn int64) error {
	ctx := context.Background()
	data := map[string]interface{}{
		"client_id": clientID,
		"user_id":   userID,
	}

	err := s.RedisClient.HSet(ctx, "refresh_token:"+token, data).Err()
	if err != nil {
		return err
	}
	return s.RedisClient.Expire(ctx, "refresh_token:"+token, time.Duration(expiresIn)*time.Second).Err()
}

// ValidateRefreshToken validates a refresh token
func (s *Service) ValidateRefreshToken(token, clientID string) (string, bool) {
	ctx := context.Background()
	result, err := s.RedisClient.HGetAll(ctx, "refresh_token:"+token).Result()
	if err != nil || len(result) == 0 {
		return "", false
	}

	if result["client_id"] != clientID {
		return "", false
	}

	return result["user_id"], true
}
