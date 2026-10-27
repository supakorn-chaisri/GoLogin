package store

import (
	"os"
	"testing"
	"time"
)

func TestStoreCreateAndGet(t *testing.T) {
	f, _ := os.CreateTemp("", "test*.db")
	f.Close()
	os.Remove(f.Name())
	s, err := New(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer os.Remove(f.Name())

	u, err := s.CreateUser("a@b.com", "secret123")
	if err != nil {
		t.Fatal(err)
	}
	if u.Email != "a@b.com" {
		t.Fatalf("email mismatch")
	}
	got, err := s.GetUserByEmail("a@b.com")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != u.ID {
		t.Fatalf("id mismatch")
	}
	if !s.CheckPassword(got, "secret123") {
		t.Fatal("password check failed")
	}
	if s.CheckPassword(got, "wrong") {
		t.Fatal("wrong password accepted")
	}
}

func TestRefreshTokenLifecycle(t *testing.T) {
	f, _ := os.CreateTemp("", "test*.db")
	f.Close()
	os.Remove(f.Name())
	s, err := New(f.Name())
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	defer os.Remove(f.Name())

	u, _ := s.CreateUser("a@b.com", "secret123")
	hash := "abc123hash"
	if err := s.SaveRefreshToken(u.ID, hash, time.Now().UTC().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	uid, err := s.ValidateRefreshToken(hash)
	if err != nil || uid != u.ID {
		t.Fatalf("validate failed: %v", err)
	}
	if err := s.RevokeRefreshToken(hash); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ValidateRefreshToken(hash); err == nil {
		t.Fatal("revoked token still valid")
	}
}
