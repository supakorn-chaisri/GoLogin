package main

import (
	"log"
	"net/http"
	"os"

	"login/internal/auth"
	"login/internal/httpapi"
	"login/internal/store"
)

func main() {
	s, err := store.New("login.db")
	if err != nil {
		log.Fatal(err)
	}
	defer s.Close()
	a := auth.New(s, getenv("JWT_SECRET", "dev-secret-change-me"))
	srv := httpapi.New(s, a)
	log.Println("listening on :8080")
	log.Fatal(http.ListenAndServe(":8080", srv.Routes()))
}

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}
