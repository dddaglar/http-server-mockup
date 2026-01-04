package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"

	"github.com/dddaglar/http_server_mockup/internal/auth"
	"github.com/dddaglar/http_server_mockup/internal/database"

	"github.com/joho/godotenv"

	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	db             *database.Queries
	jwtSecret      string
}

type userHiddenPW struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Email     string    `json:"email"`
	Token     string    `json:"token"`
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		cfg.fileserverHits.Add(1)
	})
}

func (cfg *apiConfig) metricHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	hits := cfg.fileserverHits.Load()
	NewHtml := fmt.Sprintf(`<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>`, hits)
	w.Write([]byte(NewHtml))
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, req *http.Request) {
	if os.Getenv("PLATFORM") != "dev" {
		respondWithError(w, 403, "can only be accessed in a local dev env")
		return
	}
	if err := cfg.db.DeleteAllUsers(req.Context()); err != nil {
		respondWithError(w, 500, err.Error())
		return
	}
	cfg.fileserverHits.Store(0)
	respondWithJSON(w, 200, struct {
		Valid bool `json:"valid"`
	}{Valid: true})
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	type errorResponse struct {
		Error string `json:"error"`
	}
	respondWithJSON(w, code, errorResponse{Error: msg})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	data, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, `{"error":"internal server error")`, http.StatusInternalServerError)
		return
	}
	w.Write(data)
}

func replaceProfane(s string) string {
	profanes := map[string]struct{}{
		"kerfuffle": {},
		"sharbert":  {},
		"fornax":    {},
	}
	words := strings.Fields(s)
	for i, w := range words {
		lw := strings.ToLower(w)
		if _, ok := profanes[lw]; ok {
			words[i] = "****"
		}
	}
	return strings.Join(words, " ")
}

func (cfg *apiConfig) usersHandler(w http.ResponseWriter, req *http.Request) {
	decoder := json.NewDecoder(req.Body)
	type newuser struct {
		Password string `json:"password"`
		Email    string `json:"email"`
	}
	umail := newuser{}
	if err := decoder.Decode(&umail); err != nil {
		respondWithError(w, 400, err.Error())
		return
	}
	hashedPW, err := auth.HashPassword(umail.Password)
	if err != nil {
		respondWithError(w, 500, fmt.Sprintf(`{"error": %s}`, err))
		return
	}
	user, err := cfg.db.CreateUser(req.Context(), database.CreateUserParams{
		Email:          umail.Email,
		HashedPassword: hashedPW,
	})
	if err != nil {
		respondWithError(w, 400, err.Error())
		return
	}
	respondWithJSON(w, 201, userHiddenPW{
		ID:        user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email:     user.Email,
		Token:     "", // do not return password hash
	})
}

func (cfg *apiConfig) chirpsHandler(w http.ResponseWriter, req *http.Request) {
	token, err := auth.GetBearerToken(req.Header)
	if err != nil {
		respondWithError(w, 401, "missing or invalid authorization header")
		return
	}
	userID, err := auth.ValidateJWT(token, cfg.jwtSecret)
	if err != nil {
		respondWithError(w, 401, "invalid token")
		return
	}
	decoder := json.NewDecoder(req.Body)
	type chirp struct {
		Body string `json:"body"`
	}
	params := chirp{}
	if err := decoder.Decode(&params); err != nil {
		respondWithError(w, 400, err.Error())
		return
	}
	if len(params.Body) > 140 {
		respondWithError(w, 400, "chirp too long")
		return
	}
	cleanedBody := replaceProfane(params.Body)
	newChirp, err := cfg.db.CreateChirp(req.Context(), database.CreateChirpParams{
		Body:   cleanedBody,
		UserID: userID,
	})
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}
	respondWithJSON(w, 201, newChirp)
}

func (cfg *apiConfig) getChirpsHandler(w http.ResponseWriter, req *http.Request) {
	chirps, err := cfg.db.GetChirps(req.Context())
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}
	respondWithJSON(w, 200, chirps)
}

func (cfg *apiConfig) singleChirpHandler(w http.ResponseWriter, req *http.Request) {
	id, err := uuid.Parse(req.PathValue("chirpID"))
	if err != nil {
		respondWithError(w, 400, "Invalid chirp ID")
		return
	}
	chirp, err := cfg.db.GetChirpByID(req.Context(), id)
	if err != nil {
		respondWithError(w, 404, "Chirp not found")
		return
	}
	respondWithJSON(w, 200, chirp)
}

func (cfg *apiConfig) loginHandler(w http.ResponseWriter, req *http.Request) {
	//accept this here: password, email
	decoder := json.NewDecoder(req.Body)
	type user struct {
		Password         string `json:"password"`
		Email            string `json:"email"`
		ExpiresInSeconds int64  `json:"expires_in_seconds"`
	}
	params := user{}
	if err := decoder.Decode(&params); err != nil {
		respondWithError(w, 400, err.Error())
		return
	}
	//get users entire data by email, then compare
	newUser, err := cfg.db.GetUserByMail(req.Context(), params.Email)
	if err != nil {
		respondWithError(w, 400, err.Error())
		return
	}
	ok, err := auth.CheckPasswordHash(params.Password, newUser.HashedPassword)
	if err != nil {
		respondWithError(w, 400, err.Error())
		return
	}
	if !ok {
		respondWithError(w, 401, "incorrect email or password")
		return
	}
	expiration := params.ExpiresInSeconds
	if expiration <= 0 || expiration > 3600 {
		expiration = 3600
	}
	token, err := auth.MakeJWT(newUser.ID, cfg.jwtSecret, time.Duration(expiration*int64(time.Second)))
	if err != nil {
		respondWithError(w, 500, err.Error())
		return
	}
	respondWithJSON(w, 200, userHiddenPW{
		ID:        newUser.ID,
		CreatedAt: newUser.CreatedAt,
		UpdatedAt: newUser.UpdatedAt,
		Email:     newUser.Email,
		Token:     token,
	})

}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatal("error connecting to the databasev", err)
	}

	dbQueries := database.New(db)
	jwtsecret := os.Getenv("SECRET_KEY")
	apiCfg := apiConfig{db: dbQueries, jwtSecret: jwtsecret}

	port := "8080"
	serveMux := http.NewServeMux()
	s := &http.Server{
		Addr:    ":" + port,
		Handler: serveMux,
	}
	rootHandler := http.FileServer(http.Dir("."))
	strippedAppHandler := http.StripPrefix("/app", rootHandler)
	serveMux.Handle("/app/", apiCfg.middlewareMetricsInc(strippedAppHandler))

	serveMux.Handle("GET /admin/metrics", http.HandlerFunc(apiCfg.metricHandler))
	serveMux.Handle("POST /admin/reset", http.HandlerFunc(apiCfg.resetHandler))

	serveMux.Handle("POST /api/chirps", http.HandlerFunc(apiCfg.chirpsHandler))
	serveMux.Handle("GET /api/chirps", http.HandlerFunc(apiCfg.getChirpsHandler))
	serveMux.Handle("GET /api/chirps/{chirpID}", http.HandlerFunc(apiCfg.singleChirpHandler))

	serveMux.Handle("POST /api/users", http.HandlerFunc(apiCfg.usersHandler))

	serveMux.Handle("POST /api/login", http.HandlerFunc(apiCfg.loginHandler))

	serveMux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	log.Printf("Serving on port %s\n", port)
	log.Fatal(s.ListenAndServe())
}
