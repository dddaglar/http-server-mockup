package main

import (
	"fmt"
	"log"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(w, r)
		cfg.fileserverHits.Add(1)
	})
}

func (cfg *apiConfig) metricHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	hits := cfg.fileserverHits.Load()
	fmt.Fprintf(w, "Hits: %v", hits)
}

func (cfg *apiConfig) resetHandler(w http.ResponseWriter, req *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	cfg.fileserverHits.Store(0)
}

func main() {
	port := "8080"
	serveMux := http.NewServeMux()
	s := &http.Server{
		Addr:    ":" + port,
		Handler: serveMux,
	}

	apiCfg := apiConfig{}
	rootHandler := http.FileServer(http.Dir("."))
	strippedAppHandler := http.StripPrefix("/app", rootHandler)
	serveMux.Handle("/app/", apiCfg.middlewareMetricsInc(strippedAppHandler))
	serveMux.Handle("GET /api/metrics", http.HandlerFunc(apiCfg.metricHandler))
	serveMux.Handle("POST /api/reset", http.HandlerFunc(apiCfg.resetHandler))
	serveMux.HandleFunc("GET /api/healthz", func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})

	log.Printf("Serving on port %s\n", port)
	log.Fatal(s.ListenAndServe())
}
