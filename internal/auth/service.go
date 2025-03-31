package auth

import (
	"context"
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

// StoreAuthorizationCode stores an authorization code in Redis with a 10-minute expiry
func (s *Service) StoreAuthorizationCode(code, clientID string) {
	ctx := context.Background()
	err := s.RedisClient.Set(ctx, "auth_code:"+code, clientID, 10*time.Minute).Err()
	if err != nil {
		fmt.Println("Error storing authorization code:", err)
	}
}

// ValidateAndRemoveAuthorizationCode checks if an authorization code is valid and removes it
func (s *Service) ValidateAndRemoveAuthorizationCode(code, clientID string) bool {
	ctx := context.Background()
	storedClientID, err := s.RedisClient.Get(ctx, "auth_code:"+code).Result()
	if err != nil || storedClientID != clientID {
		return false
	}
	// Delete the authorization code after successful validation
	s.RedisClient.Del(ctx, "auth_code:"+code)
	return true
}

// StoreAccessToken saves an access token with an expiration time
func (s *Service) StoreAccessToken(token, userID string, expiresIn int64) {
	ctx := context.Background()
	err := s.RedisClient.Set(ctx, "access_token:"+token, userID, time.Duration(expiresIn)*time.Second).Err()
	if err != nil {
		fmt.Println("Error storing access token:", err)
	}
}

// ValidateAccessToken checks if an access token is valid
func (s *Service) ValidateAccessToken(token string) (string, error) {
	ctx := context.Background()
	userID, err := s.RedisClient.Get(ctx, "access_token:"+token).Result()
	if err != nil {
		return "", errors.New("invalid or expired token")
	}
	return userID, nil
}
