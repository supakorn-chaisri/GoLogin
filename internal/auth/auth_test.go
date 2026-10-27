package auth

import (
	"os"
	"testing"

	"login/internal/store"
)

func TestAuthLoginAndRefresh(t *testing.T) {
	f, _ := os.CreateTemp("", "test*.db")
	f.Close()
	os.Remove(f.Name())
	s, _ := store.New(f.Name())
	defer s.Close()
	defer os.Remove(f.Name())

	a := New(s, "secret")

	s.CreateUser("a@b.com", "secret123")
	tokens, err := a.Login("a@b.com", "secret123")
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("empty tokens")
	}
	id, err := a.ValidateAccess(tokens.AccessToken)
	if err != nil || id == 0 {
		t.Fatalf("validate access: %v", err)
	}
	newTokens, err := a.Refresh(tokens.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if newTokens.AccessToken == "" {
		t.Fatal("refresh failed")
	}
	if _, err := a.Refresh(tokens.RefreshToken); err == nil {
		t.Fatal("old refresh token still valid")
	}
}

func TestAuthInvalidLogin(t *testing.T) {
	f, _ := os.CreateTemp("", "test*.db")
	f.Close()
	os.Remove(f.Name())
	s, _ := store.New(f.Name())
	defer s.Close()
	defer os.Remove(f.Name())

	a := New(s, "secret")
	s.CreateUser("a@b.com", "secret123")
	if _, err := a.Login("a@b.com", "wrong"); err == nil {
		t.Fatal("expected error")
	}
	if _, err := a.Login("nope@b.com", "secret123"); err == nil {
		t.Fatal("expected error")
	}
}
