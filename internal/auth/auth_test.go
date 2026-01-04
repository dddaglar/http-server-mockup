package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestMakeJWT(t *testing.T) {
	tests := []struct {
		name      string
		userID    uuid.UUID
		secret    string
		expiresIn time.Duration
		wantErr   bool
	}{
		{
			name:      "valid token with 1 hour expiry",
			userID:    uuid.New(),
			secret:    "test-secret",
			expiresIn: time.Hour,
			wantErr:   false,
		},
		{
			name:      "valid token with 24 hour expiry",
			userID:    uuid.New(),
			secret:    "another-secret",
			expiresIn: time.Hour * 24,
			wantErr:   false,
		},
		{
			name:      "valid token with negative expiry (already expired)",
			userID:    uuid.New(),
			secret:    "test-secret",
			expiresIn: -time.Hour,
			wantErr:   false, // MakeJWT should succeed, validation will fail
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := MakeJWT(tt.userID, tt.secret, tt.expiresIn)
			if (err != nil) != tt.wantErr {
				t.Errorf("MakeJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && token == "" {
				t.Error("MakeJWT() returned empty token")
			}
		})
	}
}

func TestValidateJWT(t *testing.T) {
	validUserID := uuid.New()
	validSecret := "test-secret"
	wrongSecret := "wrong-secret"

	// Create a valid token for use in tests
	validToken, err := MakeJWT(validUserID, validSecret, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create valid token for testing: %v", err)
	}

	// Create an expired token
	expiredToken, err := MakeJWT(validUserID, validSecret, -time.Hour)
	if err != nil {
		t.Fatalf("Failed to create expired token for testing: %v", err)
	}

	// Create a token with different secret
	differentSecretToken, err := MakeJWT(validUserID, wrongSecret, time.Hour)
	if err != nil {
		t.Fatalf("Failed to create token with different secret: %v", err)
	}

	tests := []struct {
		name       string
		token      string
		secret     string
		wantUserID uuid.UUID
		wantErr    bool
	}{
		{
			name:       "valid token with correct secret",
			token:      validToken,
			secret:     validSecret,
			wantUserID: validUserID,
			wantErr:    false,
		},
		{
			name:       "expired token",
			token:      expiredToken,
			secret:     validSecret,
			wantUserID: uuid.UUID{},
			wantErr:    true,
		},
		{
			name:       "token signed with wrong secret",
			token:      differentSecretToken,
			secret:     validSecret,
			wantUserID: uuid.UUID{},
			wantErr:    true,
		},
		{
			name:       "malformed token",
			token:      "this.is.not.a.valid.jwt",
			secret:     validSecret,
			wantUserID: uuid.UUID{},
			wantErr:    true,
		},
		{
			name:       "empty token",
			token:      "",
			secret:     validSecret,
			wantUserID: uuid.UUID{},
			wantErr:    true,
		},
		{
			name:       "token with random string",
			token:      "random-invalid-string",
			secret:     validSecret,
			wantUserID: uuid.UUID{},
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotUserID, err := ValidateJWT(tt.token, tt.secret)
			if (err != nil) != tt.wantErr {
				t.Errorf("ValidateJWT() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && gotUserID != tt.wantUserID {
				t.Errorf("ValidateJWT() gotUserID = %v, want %v", gotUserID, tt.wantUserID)
			}
		})
	}
}

func TestJWTRoundTrip(t *testing.T) {
	tests := []struct {
		name      string
		userID    uuid.UUID
		secret    string
		expiresIn time.Duration
	}{
		{
			name:      "round trip with 1 hour expiry",
			userID:    uuid.New(),
			secret:    "test-secret-123",
			expiresIn: time.Hour,
		},
		{
			name:      "round trip with 7 days expiry",
			userID:    uuid.New(),
			secret:    "another-secret-456",
			expiresIn: time.Hour * 24 * 7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create token
			token, err := MakeJWT(tt.userID, tt.secret, tt.expiresIn)
			if err != nil {
				t.Fatalf("MakeJWT() error = %v", err)
			}

			// Validate token
			gotUserID, err := ValidateJWT(token, tt.secret)
			if err != nil {
				t.Fatalf("ValidateJWT() error = %v", err)
			}

			// Verify user ID matches
			if gotUserID != tt.userID {
				t.Errorf("User ID mismatch: got %v, want %v", gotUserID, tt.userID)
			}
		})
	}
}

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "simple password",
			password: "password123",
			wantErr:  false,
		},
		{
			name:     "complex password",
			password: "C0mpl3x!P@ssw0rd#2024",
			wantErr:  false,
		},
		{
			name:     "empty password",
			password: "",
			wantErr:  false, // argon2id handles empty passwords
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)
			if (err != nil) != tt.wantErr {
				t.Errorf("HashPassword() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if hash == "" {
					t.Error("HashPassword() returned empty hash")
				}
				if hash == tt.password {
					t.Error("HashPassword() hash should not equal plain password")
				}
			}
		})
	}
}

func TestCheckPasswordHash(t *testing.T) {
	password := "test-password"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Failed to create hash for testing: %v", err)
	}

	tests := []struct {
		name      string
		password  string
		hash      string
		wantMatch bool
		wantErr   bool
	}{
		{
			name:      "correct password",
			password:  password,
			hash:      hash,
			wantMatch: true,
			wantErr:   false,
		},
		{
			name:      "wrong password",
			password:  "wrong-password",
			hash:      hash,
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "empty password against valid hash",
			password:  "",
			hash:      hash,
			wantMatch: false,
			wantErr:   false,
		},
		{
			name:      "invalid hash format",
			password:  password,
			hash:      "invalid-hash",
			wantMatch: false,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			match, err := CheckPasswordHash(tt.password, tt.hash)
			if (err != nil) != tt.wantErr {
				t.Errorf("CheckPasswordHash() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if match != tt.wantMatch {
				t.Errorf("CheckPasswordHash() match = %v, want %v", match, tt.wantMatch)
			}
		})
	}
}

func TestPasswordHashUniqueness(t *testing.T) {
	password := "same-password"

	// Hash the same password twice
	hash1, err := HashPassword(password)
	if err != nil {
		t.Fatalf("First HashPassword() error = %v", err)
	}

	hash2, err := HashPassword(password)
	if err != nil {
		t.Fatalf("Second HashPassword() error = %v", err)
	}

	// Hashes should be different (due to random salt)
	if hash1 == hash2 {
		t.Error("HashPassword() should produce different hashes due to random salt")
	}

	// But both should validate correctly
	match1, err := CheckPasswordHash(password, hash1)
	if err != nil || !match1 {
		t.Errorf("First hash validation failed: match=%v, err=%v", match1, err)
	}

	match2, err := CheckPasswordHash(password, hash2)
	if err != nil || !match2 {
		t.Errorf("Second hash validation failed: match=%v, err=%v", match2, err)
	}
}

func TestGetBearerToken(t *testing.T) {
	//test happy path,
	// test if the authorization header doesnt exist,
	tests := []struct {
		name      string
		headers   http.Header
		wantToken string
		wantErr   bool
	}{
		{
			name:      "happy path",
			headers:   http.Header{"Authorization": []string{"Bearer validstring"}},
			wantToken: "validstring",
			wantErr:   false,
		},
		{
			name:      "missing bearer prefix",
			headers:   http.Header{"Authorization": []string{"Bearer"}},
			wantToken: "",
			wantErr:   true,
		},
		{
			name:      "missing bearer prefix with one space",
			headers:   http.Header{"Authorization": []string{"Bearer "}},
			wantToken: "",
			wantErr:   false,
		},
		{
			name:      "no authorization header",
			headers:   http.Header{},
			wantToken: "",
			wantErr:   true,
		},
		{
			name:      "valid token with different string",
			headers:   http.Header{"Authorization": []string{"Basic username:password"}},
			wantToken: "",
			wantErr:   true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GetBearerToken(tt.headers)
			if (err != nil) != tt.wantErr {
				t.Errorf("GetBearerToken() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if token != tt.wantToken {
				t.Errorf("GetBearerToken() got = %v, want %v", token, tt.wantToken)
			}
		})
	}
}
