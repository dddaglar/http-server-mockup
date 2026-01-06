package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/dddaglar/http_server_mockup/internal/auth"
	"github.com/dddaglar/http_server_mockup/internal/database"
	"github.com/google/uuid"
	_ "github.com/lib/pq"
)

// HELPER FUNCTION TESTS (No Database Required)
// These tests validate core utility functions that don't depend on external
// services like databases. They're fast, isolated, and should run first.

// TestReplaceProfane tests the profanity filter function
// This is a pure function (no side effects), making it ideal for unit testing
func TestReplaceProfane(t *testing.T) {
	// Table-driven tests: a Go best practice that allows testing multiple
	// scenarios with the same test logic. Each test case is self-documenting.
	tests := []struct {
		name  string // Describes what we're testing
		input string // The string to filter
		want  string // Expected output
	}{
		{
			name:  "no profanity - returns unchanged",
			input: "This is a clean message",
			want:  "This is a clean message",
		},
		{
			name:  "single profane word - kerfuffle",
			input: "This is a kerfuffle",
			want:  "This is a ****",
		},
		{
			name:  "single profane word - sharbert",
			input: "I love sharbert",
			want:  "I love ****",
		},
		{
			name:  "single profane word - fornax",
			input: "fornax is bad",
			want:  "**** is bad",
		},
		{
			name:  "case insensitive - uppercase",
			input: "This is a KERFUFFLE",
			want:  "This is a ****",
		},
		{
			name:  "case insensitive - mixed case",
			input: "What a KeRfUfFlE",
			want:  "What a ****",
		},
		{
			name:  "multiple profane words",
			input: "kerfuffle and sharbert are both bad",
			want:  "**** and **** are both bad",
		},
		{
			name:  "profane word at start",
			input: "Kerfuffle is the first word",
			want:  "**** is the first word",
		},
		{
			name:  "profane word at end",
			input: "The last word is fornax",
			want:  "The last word is ****",
		},
		{
			name:  "all three profane words",
			input: "kerfuffle sharbert fornax",
			want:  "**** **** ****",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "single word - not profane",
			input: "hello",
			want:  "hello",
		},
		{
			name:  "normalizes multiple spaces to single space",
			input: "this  has  extra  spaces",
			want:  "this has extra spaces",
		},
	}

	// Run each test case
	for _, tt := range tests {
		// t.Run creates a subtest - this gives better error messages and allows
		// running individual tests with: go test -run TestReplaceProfane/name
		t.Run(tt.name, func(t *testing.T) {
			got := replaceProfane(tt.input)
			if got != tt.want {
				// Clear error message shows what went wrong
				t.Errorf("replaceProfane(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestRespondWithJSON tests the JSON response helper function
// This validates that our API responses are correctly formatted
func TestRespondWithJSON(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		payload        interface{}
		wantStatusCode int
		wantBody       string
		wantHeader     string
	}{
		{
			name:           "simple string payload",
			statusCode:     200,
			payload:        map[string]string{"message": "hello"},
			wantStatusCode: 200,
			wantBody:       `{"message":"hello"}`,
			wantHeader:     "application/json",
		},
		{
			name:           "201 created status",
			statusCode:     201,
			payload:        map[string]string{"status": "created"},
			wantStatusCode: 201,
			wantBody:       `{"status":"created"}`,
			wantHeader:     "application/json",
		},
		{
			name:           "nested object",
			statusCode:     200,
			payload:        map[string]interface{}{"user": map[string]string{"name": "test"}},
			wantStatusCode: 200,
			wantBody:       `{"user":{"name":"test"}}`,
			wantHeader:     "application/json",
		},
		{
			name:           "array payload",
			statusCode:     200,
			payload:        []string{"item1", "item2"},
			wantStatusCode: 200,
			wantBody:       `["item1","item2"]`,
			wantHeader:     "application/json",
		},
		{
			name:           "empty object",
			statusCode:     200,
			payload:        map[string]string{},
			wantStatusCode: 200,
			wantBody:       `{}`,
			wantHeader:     "application/json",
		},
		{
			name:           "boolean value",
			statusCode:     200,
			payload:        map[string]bool{"valid": true},
			wantStatusCode: 200,
			wantBody:       `{"valid":true}`,
			wantHeader:     "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// httptest.NewRecorder captures the HTTP response
			// This is the standard way to test HTTP handlers in Go
			w := httptest.NewRecorder()

			// Call the function we're testing
			respondWithJSON(w, tt.statusCode, tt.payload)

			// Verify status code
			if w.Code != tt.wantStatusCode {
				t.Errorf("status code = %d, want %d", w.Code, tt.wantStatusCode)
			}

			// Verify Content-Type header is set correctly
			// This is important for clients to parse the response
			gotHeader := w.Header().Get("Content-Type")
			if gotHeader != tt.wantHeader {
				t.Errorf("Content-Type = %q, want %q", gotHeader, tt.wantHeader)
			}

			// Verify JSON body - trim whitespace for comparison
			gotBody := strings.TrimSpace(w.Body.String())
			if gotBody != tt.wantBody {
				t.Errorf("body = %q, want %q", gotBody, tt.wantBody)
			}

			// Verify the response is valid JSON (can be unmarshaled)
			var jsonCheck interface{}
			if err := json.Unmarshal(w.Body.Bytes(), &jsonCheck); err != nil {
				t.Errorf("response is not valid JSON: %v", err)
			}
		})
	}
}

// TestRespondWithError tests the error response helper
// Ensures all error responses follow the same format: {"error": "message"}
func TestRespondWithError(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		errorMsg       string
		wantStatusCode int
		wantErrorMsg   string
	}{
		{
			name:           "400 bad request",
			statusCode:     400,
			errorMsg:       "invalid input",
			wantStatusCode: 400,
			wantErrorMsg:   "invalid input",
		},
		{
			name:           "401 unauthorized",
			statusCode:     401,
			errorMsg:       "missing or invalid authorization header",
			wantStatusCode: 401,
			wantErrorMsg:   "missing or invalid authorization header",
		},
		{
			name:           "403 forbidden",
			statusCode:     403,
			errorMsg:       "forbidden: not the owner of the chirp",
			wantStatusCode: 403,
			wantErrorMsg:   "forbidden: not the owner of the chirp",
		},
		{
			name:           "404 not found",
			statusCode:     404,
			errorMsg:       "Chirp not found",
			wantStatusCode: 404,
			wantErrorMsg:   "Chirp not found",
		},
		{
			name:           "500 internal server error",
			statusCode:     500,
			errorMsg:       "database error",
			wantStatusCode: 500,
			wantErrorMsg:   "database error",
		},
		{
			name:           "empty error message",
			statusCode:     400,
			errorMsg:       "",
			wantStatusCode: 400,
			wantErrorMsg:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()

			respondWithError(w, tt.statusCode, tt.errorMsg)

			// Verify status code
			if w.Code != tt.wantStatusCode {
				t.Errorf("status code = %d, want %d", w.Code, tt.wantStatusCode)
			}

			// Verify Content-Type header
			gotHeader := w.Header().Get("Content-Type")
			if gotHeader != "application/json" {
				t.Errorf("Content-Type = %q, want %q", gotHeader, "application/json")
			}

			// Parse the JSON response to verify structure
			var response struct {
				Error string `json:"error"`
			}
			if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
				t.Fatalf("failed to decode response: %v", err)
			}

			// Verify error message matches
			if response.Error != tt.wantErrorMsg {
				t.Errorf("error message = %q, want %q", response.Error, tt.wantErrorMsg)
			}
		})
	}
}

// MIDDLEWARE TESTS
// Middleware wraps handlers to add cross-cutting concerns like metrics

// TestMiddlewareMetricsInc tests the metrics middleware
func TestMiddlewareMetricsInc(t *testing.T) {
	t.Run("increments counter after request", func(t *testing.T) {
		// Create a fresh apiConfig for this test
		cfg := &apiConfig{}

		// Create a simple handler that the middleware will wrap
		// This handler just returns 200 OK
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})

		// Wrap the handler with our middleware
		wrappedHandler := cfg.middlewareMetricsInc(nextHandler)

		// Make a request through the middleware
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		// Verify the counter was incremented
		if got := cfg.fileserverHits.Load(); got != 1 {
			t.Errorf("hits = %d, want 1", got)
		}
	})

	t.Run("increments for multiple requests", func(t *testing.T) {
		cfg := &apiConfig{}
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		wrappedHandler := cfg.middlewareMetricsInc(nextHandler)

		// Make 5 requests
		for i := 0; i < 5; i++ {
			req := httptest.NewRequest(http.MethodGet, "/test", nil)
			w := httptest.NewRecorder()
			wrappedHandler.ServeHTTP(w, req)
		}

		// Verify counter shows 5
		if got := cfg.fileserverHits.Load(); got != 5 {
			t.Errorf("hits after 5 requests = %d, want 5", got)
		}
	})

	t.Run("calls next handler", func(t *testing.T) {
		cfg := &apiConfig{}

		// Track if the next handler was called
		handlerCalled := false
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			handlerCalled = true
			w.WriteHeader(http.StatusOK)
		})

		wrappedHandler := cfg.middlewareMetricsInc(nextHandler)

		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		w := httptest.NewRecorder()
		wrappedHandler.ServeHTTP(w, req)

		// Verify the next handler was actually called
		if !handlerCalled {
			t.Error("middleware did not call next handler")
		}
	})

	t.Run("thread safe - concurrent requests", func(t *testing.T) {
		cfg := &apiConfig{}
		nextHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
		wrappedHandler := cfg.middlewareMetricsInc(nextHandler)

		// Use WaitGroup to synchronize goroutines
		// This ensures all 100 requests complete before we check the count
		var wg sync.WaitGroup
		numRequests := 100

		// Launch 100 concurrent requests
		// This tests that atomic.Int32 is thread-safe
		for i := 0; i < numRequests; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req := httptest.NewRequest(http.MethodGet, "/test", nil)
				w := httptest.NewRecorder()
				wrappedHandler.ServeHTTP(w, req)
			}()
		}

		// Wait for all requests to complete
		wg.Wait()

		// Verify no increments were lost due to race conditions
		if got := cfg.fileserverHits.Load(); got != int32(numRequests) {
			t.Errorf("hits after %d concurrent requests = %d, want %d", numRequests, got, numRequests)
		}
	})
}

// SIMPLE ENDPOINT TESTS (No Database Required)

// TestHealthzHandler tests the health check endpoint
// This is the simplest endpoint - perfect for testing basic HTTP behavior
func HealthzHandlerHelper(t *testing.T) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, "/api/healthz", nil)
	w := httptest.NewRecorder()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	mux.ServeHTTP(w, req)

	return w
}
func TestHealthzHandler(t *testing.T) {
	w := HealthzHandlerHelper(t)
	tests := []struct {
		name  string
		check func(t *testing.T)
	}{
		{
			name: "returns 200 OK",
			check: func(t *testing.T) {
				// Create the request
				w := HealthzHandlerHelper(t)
				// Verify status code
				if w.Code != http.StatusOK {
					t.Errorf("status code = %d, want %d", w.Code, http.StatusOK)
				}
			},
		},
		{
			name: "returns OK in body",
			check: func(t *testing.T) {
				w := HealthzHandlerHelper(t)
				// Verify response body
				if got := w.Body.String(); got != "OK" {
					t.Errorf("body = %q, want %q", got, "OK")
				}
			},
		},
		{
			name: "sets correct Content-Type header",
			check: func(t *testing.T) {
				w := HealthzHandlerHelper(t)
				// Verify Content-Type header
				want := "text/plain; charset=utf-8"
				if got := w.Header().Get("Content-Type"); got != want {
					t.Errorf("Content-Type = %q, want %q", got, want)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.check(t)
		})
	}
}

// TestMetricHandler tests the admin metrics endpoint
func TestMetricHandler(t *testing.T) {
	t.Run("returns 200 OK", func(t *testing.T) {
		cfg := &apiConfig{}
		req := httptest.NewRequest(http.MethodGet, "/admin/metrics", nil)
		w := httptest.NewRecorder()

		cfg.metricHandler(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("status code = %d, want %d", w.Code, http.StatusOK)
		}
	})

	t.Run("returns HTML content type", func(t *testing.T) {
		cfg := &apiConfig{}
		req := httptest.NewRequest(http.MethodGet, "/admin/metrics", nil)
		w := httptest.NewRecorder()

		cfg.metricHandler(w, req)

		want := "text/html; charset=utf-8"
		if got := w.Header().Get("Content-Type"); got != want {
			t.Errorf("Content-Type = %q, want %q", got, want)
		}
	})

	t.Run("displays correct hit count - zero", func(t *testing.T) {
		cfg := &apiConfig{}
		// Don't increment, should be 0
		req := httptest.NewRequest(http.MethodGet, "/admin/metrics", nil)
		w := httptest.NewRecorder()

		cfg.metricHandler(w, req)

		body := w.Body.String()
		// Should contain "0 times" in the HTML
		if !strings.Contains(body, "0 times") {
			t.Errorf("body should contain '0 times', got: %s", body)
		}
	})

	t.Run("displays correct hit count - after increments", func(t *testing.T) {
		cfg := &apiConfig{}
		// Increment counter 5 times
		cfg.fileserverHits.Store(5)

		req := httptest.NewRequest(http.MethodGet, "/admin/metrics", nil)
		w := httptest.NewRecorder()

		cfg.metricHandler(w, req)

		body := w.Body.String()
		// Should contain "5 times" in the HTML
		if !strings.Contains(body, "5 times") {
			t.Errorf("body should contain '5 times', got: %s", body)
		}
	})

	t.Run("contains expected HTML elements", func(t *testing.T) {
		cfg := &apiConfig{}
		req := httptest.NewRequest(http.MethodGet, "/admin/metrics", nil)
		w := httptest.NewRecorder()

		cfg.metricHandler(w, req)

		body := w.Body.String()

		// Verify HTML structure
		requiredElements := []string{
			"<html>",
			"<body>",
			"<h1>Welcome, Chirpy Admin</h1>",
			"Chirpy has been visited",
			"</body>",
			"</html>",
		}

		for _, element := range requiredElements {
			if !strings.Contains(body, element) {
				t.Errorf("body missing expected element: %q", element)
			}
		}
	})
}

// TestResetHandler_NonDevEnvironment tests the reset endpoint in non-dev mode
// This is a UNIT test because we're only testing the environment check,
// not the actual database reset (that's an integration test)
func TestResetHandler_NonDevEnvironment(t *testing.T) {
	// Save original environment variable
	originalPlatform := os.Getenv("PLATFORM")
	defer func() {
		// Restore it after test
		os.Setenv("PLATFORM", originalPlatform)
	}()

	t.Run("returns 403 when not in dev environment", func(t *testing.T) {
		// Set environment to production
		os.Setenv("PLATFORM", "prod")

		cfg := &apiConfig{}
		req := httptest.NewRequest(http.MethodPost, "/admin/reset", nil)
		w := httptest.NewRecorder()

		cfg.resetHandler(w, req)

		// Should return 403 Forbidden
		if w.Code != http.StatusForbidden {
			t.Errorf("status code = %d, want %d", w.Code, http.StatusForbidden)
		}
	})

	t.Run("returns correct error message for non-dev", func(t *testing.T) {
		os.Setenv("PLATFORM", "production")

		cfg := &apiConfig{}
		req := httptest.NewRequest(http.MethodPost, "/admin/reset", nil)
		w := httptest.NewRecorder()

		cfg.resetHandler(w, req)

		// Parse response
		var response struct {
			Error string `json:"error"`
		}
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		// Verify error message
		want := "can only be accessed in a local dev env"
		if response.Error != want {
			t.Errorf("error message = %q, want %q", response.Error, want)
		}
	})

	t.Run("returns JSON content type even on error", func(t *testing.T) {
		os.Setenv("PLATFORM", "staging")

		cfg := &apiConfig{}
		req := httptest.NewRequest(http.MethodPost, "/admin/reset", nil)
		w := httptest.NewRecorder()

		cfg.resetHandler(w, req)

		if got := w.Header().Get("Content-Type"); got != "application/json" {
			t.Errorf("Content-Type = %q, want %q", got, "application/json")
		}
	})
}

// INTEGRATION TESTS (Require Database)

// These tests use a real PostgreSQL database to test full request/response
// cycles including database operations.

// setupTestDB creates a test database connection and returns cleanup function
// This function:
// 1. Connects to a SEPARATE test database (not your dev database!)
// 2. Schema should already exist (run migrations manually on test DB)
// 3. Returns *database.Queries for use in tests
// 4. Registers a cleanup function to truncate tables after each test
func setupTestDB(t *testing.T) *database.Queries {
	// IMPORTANT: Use TEST_DB_URL if set, otherwise fall back to DB_URL
	// This allows you to specify a separate test database
	dbURL := os.Getenv("TEST_DB_URL")
	if dbURL == "" {
		// Fall back to DB_URL, but this is NOT recommended for production
		dbURL = os.Getenv("DB_URL")
		if dbURL == "" {
			t.Skip("Neither TEST_DB_URL nor DB_URL set, skipping integration tests")
		}
		// Warn that we're using the dev database
		t.Logf("WARNING: TEST_DB_URL not set, using DB_URL. This may delete dev data!")
	}

	// Connect to PostgreSQL test database
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}

	// Verify connection works
	if err := db.Ping(); err != nil {
		t.Fatalf("failed to ping test database: %v", err)
	}

	// Create database queries instance
	dbQueries := database.New(db)

	// Register cleanup function to run after test completes
	// This ensures tests don't interfere with each other
	t.Cleanup(func() {
		// Clean up test data in reverse order of foreign key dependencies
		// IMPORTANT: This deletes ALL data, so use a dedicated test database

		// Delete in order: chirps -> tokens -> users (respects foreign keys)
		db.Exec("DELETE FROM chirps")
		db.Exec("DELETE FROM tokens")
		db.Exec("DELETE FROM users")

		// Close database connection
		db.Close()
	})

	return dbQueries
}

// USER MANAGEMENT INTEGRATION TESTS

// TestUsersHandler_Integration tests the user creation endpoint with real database
func TestUsersHandler_Integration(t *testing.T) {
	// Set up test database
	dbQueries := setupTestDB(t)

	// Create apiConfig with test database
	cfg := &apiConfig{
		db:        dbQueries,
		jwtSecret: "test-secret-key",
	}

	t.Run("creates user successfully", func(t *testing.T) {
		// Prepare request body with user data
		reqBody := `{"email":"test@example.com","password":"securepassword123"}`
		req := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")

		// Create response recorder
		w := httptest.NewRecorder()

		// Call the handler
		cfg.usersHandler(w, req)

		// VERIFY: Status code should be 201 Created
		if w.Code != http.StatusCreated {
			t.Errorf("status code = %d, want %d. Body: %s", w.Code, http.StatusCreated, w.Body.String())
		}

		// VERIFY: Response should be valid JSON
		var response userHiddenPW
		if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}

		// VERIFY: Response contains expected fields
		if response.Email != "test@example.com" {
			t.Errorf("email = %q, want %q", response.Email, "test@example.com")
		}
		if response.ID == uuid.Nil {
			t.Error("user ID should not be nil")
		}
		if response.CreatedAt.IsZero() {
			t.Error("created_at should not be zero")
		}
		if response.UpdatedAt.IsZero() {
			t.Error("updated_at should not be zero")
		}

		// VERIFY: Password and tokens are NOT returned (security)
		if response.Token != "" {
			t.Error("token should be empty in user creation response")
		}
		if response.RefreshToken != "" {
			t.Error("refresh_token should be empty in user creation response")
		}

		// VERIFY: User is actually in the database
		ctx := context.Background()
		dbUser, err := dbQueries.GetUserByMail(ctx, "test@example.com")
		if err != nil {
			t.Fatalf("failed to retrieve user from database: %v", err)
		}

		// VERIFY: Database user matches response
		if dbUser.ID != response.ID {
			t.Errorf("database user ID = %v, want %v", dbUser.ID, response.ID)
		}
		if dbUser.Email != "test@example.com" {
			t.Errorf("database user email = %q, want %q", dbUser.Email, "test@example.com")
		}

		// VERIFY: Password is hashed, not stored in plaintext
		if dbUser.HashedPassword == "securepassword123" {
			t.Error("password should be hashed, not stored as plaintext")
		}
		// Hashed password should be non-empty and different from original
		if dbUser.HashedPassword == "" {
			t.Error("hashed password should not be empty")
		}
	})
}

// AUTHENTICATION INTEGRATION TESTS

// TestLoginHandler_Integration tests the login endpoint with real database
func TestLoginHandler_Integration(t *testing.T) {
	// Set up test database
	dbQueries := setupTestDB(t)

	cfg := &apiConfig{
		db:        dbQueries,
		jwtSecret: "test-secret-key",
	}

	t.Run("login with valid credentials", func(t *testing.T) {
		// SETUP: First create a user to login with
		createReqBody := `{"email":"login@example.com","password":"mypassword123"}`
		createReq := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(createReqBody))
		createReq.Header.Set("Content-Type", "application/json")
		createW := httptest.NewRecorder()
		cfg.usersHandler(createW, createReq)

		// Verify user creation succeeded before testing login
		if createW.Code != http.StatusCreated {
			t.Fatalf("failed to create test user: status %d, body: %s", createW.Code, createW.Body.String())
		}

		// TEST: Now attempt to login with the same credentials
		loginReqBody := `{"email":"login@example.com","password":"mypassword123"}`
		loginReq := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(loginReqBody))
		loginReq.Header.Set("Content-Type", "application/json")
		loginW := httptest.NewRecorder()

		// Call login handler
		cfg.loginHandler(loginW, loginReq)

		// VERIFY: Status code should be 200 OK
		if loginW.Code != http.StatusOK {
			t.Errorf("status code = %d, want %d. Body: %s", loginW.Code, http.StatusOK, loginW.Body.String())
		}

		// VERIFY: Response contains user data and tokens
		var response userHiddenPW
		if err := json.NewDecoder(loginW.Body).Decode(&response); err != nil {
			t.Fatalf("failed to decode login response: %v", err)
		}

		// VERIFY: Email matches
		if response.Email != "login@example.com" {
			t.Errorf("email = %q, want %q", response.Email, "login@example.com")
		}

		// VERIFY: Access token (JWT) is returned
		if response.Token == "" {
			t.Error("access token should not be empty")
		}

		// VERIFY: Refresh token is returned
		if response.RefreshToken == "" {
			t.Error("refresh token should not be empty")
		}

		// VERIFY: Access token is valid JWT
		// We can decode it to verify it contains the user ID
		userID, err := auth.ValidateJWT(response.Token, "test-secret-key")
		if err != nil {
			t.Errorf("JWT validation failed: %v", err)
		}
		if userID != response.ID {
			t.Errorf("JWT contains user ID %v, want %v", userID, response.ID)
		}

		// VERIFY: Refresh token is stored in database
		ctx := context.Background()
		dbToken, err := dbQueries.GetRefreshToken(ctx, response.RefreshToken)
		if err != nil {
			t.Fatalf("refresh token not found in database: %v", err)
		}

		// VERIFY: Refresh token is associated with correct user
		if dbToken.UserID != response.ID {
			t.Errorf("refresh token user ID = %v, want %v", dbToken.UserID, response.ID)
		}

		// VERIFY: Refresh token has expiration set (should be 60 days from now)
		if dbToken.ExpiresAt.IsZero() {
			t.Error("refresh token should have expiration time set")
		}
		// Should not be revoked yet
		if dbToken.RevokedAt.Valid {
			t.Error("refresh token should not be revoked on creation")
		}
	})
}

// CHIRPS INTEGRATION TESTS

// TestChirpsHandler_Integration tests creating chirps with authentication
func TestChirpsHandler_Integration(t *testing.T) {
	// Set up test database
	dbQueries := setupTestDB(t)

	cfg := &apiConfig{
		db:        dbQueries,
		jwtSecret: "test-secret-key",
	}

	t.Run("creates chirp with valid auth token", func(t *testing.T) {
		// SETUP: Create a user and login to get auth token
		createUserBody := `{"email":"chirper@example.com","password":"password123"}`
		createUserReq := httptest.NewRequest(http.MethodPost, "/api/users", strings.NewReader(createUserBody))
		createUserReq.Header.Set("Content-Type", "application/json")
		createUserW := httptest.NewRecorder()
		cfg.usersHandler(createUserW, createUserReq)

		// Get user ID from creation response
		var createdUser userHiddenPW
		json.NewDecoder(createUserW.Body).Decode(&createdUser)

		// Login to get access token
		loginBody := `{"email":"chirper@example.com","password":"password123"}`
		loginReq := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(loginBody))
		loginReq.Header.Set("Content-Type", "application/json")
		loginW := httptest.NewRecorder()
		cfg.loginHandler(loginW, loginReq)

		// Extract access token from login response
		var loginResp userHiddenPW
		if err := json.NewDecoder(loginW.Body).Decode(&loginResp); err != nil {
			t.Fatalf("failed to decode login response: %v", err)
		}
		accessToken := loginResp.Token

		// TEST: Create a chirp with the access token
		chirpBody := `{"body":"This is my test chirp with kerfuffle word"}`
		chirpReq := httptest.NewRequest(http.MethodPost, "/api/chirps", strings.NewReader(chirpBody))
		chirpReq.Header.Set("Content-Type", "application/json")
		// IMPORTANT: Set Authorization header with Bearer token
		chirpReq.Header.Set("Authorization", "Bearer "+accessToken)
		chirpW := httptest.NewRecorder()

		// Call chirps handler
		cfg.chirpsHandler(chirpW, chirpReq)

		// VERIFY: Status code should be 201 Created
		if chirpW.Code != http.StatusCreated {
			t.Errorf("status code = %d, want %d. Body: %s", chirpW.Code, http.StatusCreated, chirpW.Body.String())
		}

		// VERIFY: Response contains chirp data
		var response database.Chirp
		if err := json.NewDecoder(chirpW.Body).Decode(&response); err != nil {
			t.Fatalf("failed to decode chirp response: %v", err)
		}

		// VERIFY: Chirp has valid ID
		if response.ID == uuid.Nil {
			t.Error("chirp ID should not be nil")
		}

		// VERIFY: Chirp is associated with correct user
		if response.UserID != createdUser.ID {
			t.Errorf("chirp user ID = %v, want %v", response.UserID, createdUser.ID)
		}

		// VERIFY: Profanity filter was applied (kerfuffle -> ****)
		expectedBody := "This is my test chirp with **** word"
		if response.Body != expectedBody {
			t.Errorf("chirp body = %q, want %q (profanity should be filtered)", response.Body, expectedBody)
		}

		// VERIFY: Timestamps are set
		if response.CreatedAt.IsZero() {
			t.Error("chirp created_at should not be zero")
		}
		if response.UpdatedAt.IsZero() {
			t.Error("chirp updated_at should not be zero")
		}

		// VERIFY: Chirp is actually in the database
		ctx := context.Background()
		dbChirp, err := dbQueries.GetChirpByID(ctx, response.ID)
		if err != nil {
			t.Fatalf("failed to retrieve chirp from database: %v", err)
		}

		// VERIFY: Database chirp matches response
		if dbChirp.ID != response.ID {
			t.Errorf("database chirp ID = %v, want %v", dbChirp.ID, response.ID)
		}
		if dbChirp.Body != expectedBody {
			t.Errorf("database chirp body = %q, want %q", dbChirp.Body, expectedBody)
		}
		if dbChirp.UserID != createdUser.ID {
			t.Errorf("database chirp user ID = %v, want %v", dbChirp.UserID, createdUser.ID)
		}
	})
}
