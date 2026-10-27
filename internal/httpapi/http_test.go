package httpapi

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"login/internal/auth"
	"login/internal/store"
)

func setup(t *testing.T) (*Server, func()) {
	f, _ := os.CreateTemp("", "test*.db")
	f.Close()
	os.Remove(f.Name())
	s, _ := store.New(f.Name())
	a := auth.New(s, "secret")
	srv := New(s, a)
	cleanup := func() { s.Close(); os.Remove(f.Name()) }
	return srv, cleanup
}

func TestHTTPSignupLoginMe(t *testing.T) {
	srv, cleanup := setup(t)
	defer cleanup()

	// signup
	body, _ := json.Marshal(map[string]string{"email": "a@b.com", "password": "secret123"})
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("signup: %d %s", w.Code, w.Body.String())
	}

	// login
	req = httptest.NewRequest("POST", "/login", bytes.NewReader(body))
	w = httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
	var tokens map[string]string
	json.Unmarshal(w.Body.Bytes(), &tokens)

	// me
	req = httptest.NewRequest("GET", "/me", nil)
	req.Header.Set("Authorization", "Bearer "+tokens["access_token"])
	w = httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("me: %d %s", w.Code, w.Body.String())
	}

	// refresh
	rb, _ := json.Marshal(map[string]string{"refresh_token": tokens["refresh_token"]})
	req = httptest.NewRequest("POST", "/refresh", bytes.NewReader(rb))
	w = httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("refresh: %d %s", w.Code, w.Body.String())
	}
}

func TestHTTPInvalidLogin(t *testing.T) {
	srv, cleanup := setup(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{"email": "a@b.com", "password": "secret123"})
	req := httptest.NewRequest("POST", "/signup", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)

	body, _ = json.Marshal(map[string]string{"email": "a@b.com", "password": "wrong"})
	req = httptest.NewRequest("POST", "/login", bytes.NewReader(body))
	w = httptest.NewRecorder()
	srv.Routes().ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", w.Code)
	}
}
