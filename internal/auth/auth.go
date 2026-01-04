package auth

import (
	"encoding/hex"
	"time"

	"net/http"
	"strings"

	"crypto/rand"

	"github.com/alexedwards/argon2id"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

func HashPassword(password string) (string, error) {
	//argon2id.CreateHash
	hash, err := argon2id.CreateHash(password, argon2id.DefaultParams)
	if err != nil {
		return "", err
	}
	return hash, nil
}

func CheckPasswordHash(password, hash string) (bool, error) {
	match, err := argon2id.ComparePasswordAndHash(password, hash)
	if err != nil {
		return false, err
	}
	return match, nil
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	newToken := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		Subject:   userID.String(),
	})
	return newToken.SignedString([]byte(tokenSecret))
}

func ValidateJWT(tokenString, secret string) (uuid.UUID, error) {
	claims := &jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (any, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return uuid.UUID{}, err
	}
	userIDStr := token.Claims.(*jwt.RegisteredClaims).Subject
	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		return uuid.UUID{}, err
	}
	return userID, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	bearer := headers.Get("Authorization")
	if bearer == "" {
		return "", http.ErrNoCookie
	}
	tokenString := strings.SplitN(bearer, " ", 2)
	if len(tokenString) != 2 || strings.ToLower(tokenString[0]) != "bearer" {
		return "", http.ErrNoCookie
	}
	return tokenString[1], nil
}

func MakeRefreshToken() (string, error) {
	newTokenUUID := make([]byte, 32)
	_, err := rand.Read(newTokenUUID)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(newTokenUUID), nil
}
