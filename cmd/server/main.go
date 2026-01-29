// 0cdn server: API, auth, routing, opt DNS (.0cdn).
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"dev.c0redev.0cdn/internal/server/api"
	"dev.c0redev.0cdn/internal/server/dns"
	"dev.c0redev.0cdn/internal/store"
)

func logRequest(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sw := &statusWriter{ResponseWriter: w, code: 200}
		next.ServeHTTP(sw, r)
		if sw.code >= 400 {
			log.Printf("api %s %s %d", r.Method, r.URL.Path, sw.code)
		}
	})
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	w.code = code
	w.ResponseWriter.WriteHeader(code)
}

func main() {
	dbPath := os.Getenv("0CDN_DB")
	if dbPath == "" {
		dbPath = "0cdn.db"
	}
	db, err := store.Open(dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	mux := http.NewServeMux()
	srv := api.New(db)
	srv.Mount(mux)
	maxBodyMB := 1
	if s := os.Getenv("0CDN_MAX_BODY_MB"); s != "" {
		if n, err := strconv.Atoi(s); err == nil && n > 0 && n <= 64 {
			maxBodyMB = n
		}
	}
	maxBodyBytes := int64(maxBodyMB) * (1 << 20)
	limitBody := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
			next.ServeHTTP(w, r)
		})
	}
	handler := logRequest(limitBody(api.CORS(mux)))

	addr := os.Getenv("0CDN_SERVER_ADDR")
	if addr == "" {
		addr = ":8443"
	}
	httpSrv := &http.Server{Addr: addr, Handler: handler}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if dnsAddr := os.Getenv("0CDN_DNS_ADDR"); dnsAddr != "" {
		dnsSrv := dns.New(db, dnsAddr)
		go func() {
			if err := dnsSrv.Run(ctx); err != nil && err != context.Canceled {
				log.Println("dns:", err)
			}
		}()
		log.Println("dns listening on", dnsAddr)
	}

	go func() {
		log.Println("server listening on", addr)
		if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := httpSrv.Shutdown(shutdownCtx); err != nil {
		log.Println("server shutdown:", err)
	}
}
