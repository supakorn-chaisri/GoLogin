package httpapi

import (
	"encoding/json"
	"net/http"

	"login/internal/auth"
	"login/internal/store"
)

type Server struct {
	store *store.Store
	auth  *auth.Service
}

func New(s *store.Store, a *auth.Service) *Server {
	return &Server{store: s, auth: a}
}

func (sv *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /signup", sv.signup)
	mux.HandleFunc("POST /login", sv.login)
	mux.HandleFunc("POST /refresh", sv.refresh)
	mux.HandleFunc("GET /me", sv.me)
	return mux
}

func (sv *Server) signup(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	u, err := sv.store.CreateUser(body.Email, body.Password)
	if err != nil {
		http.Error(w, "could not create user", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"id": u.ID, "email": u.Email})
}

func (sv *Server) login(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	tokens, err := sv.auth.Login(body.Email, body.Password)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}

func (sv *Server) refresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	tokens, err := sv.auth.Refresh(body.RefreshToken)
	if err != nil {
		http.Error(w, "invalid refresh token", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(tokens)
}

func (sv *Server) me(w http.ResponseWriter, r *http.Request) {
	authz := r.Header.Get("Authorization")
	if len(authz) < 8 {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	id, err := sv.auth.ValidateAccess(authz[7:])
	if err != nil {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	u, err := sv.store.GetUserByID(id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"id": u.ID, "email": u.Email, "role": u.Role})
}
