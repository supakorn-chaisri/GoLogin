package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"login/internal/store"
)

type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
}

type Service struct {
	store  *store.Store
	secret []byte
}

func New(store *store.Store, secret string) *Service {
	return &Service{store: store, secret: []byte(secret)}
}

func (a *Service) Login(email, password string) (*Tokens, error) {
	u, err := a.store.GetUserByEmail(email)
	if err != nil {
		return nil, errors.New("invalid credentials")
	}
	if !a.store.CheckPassword(u, password) {
		return nil, errors.New("invalid credentials")
	}
	return a.issue(u.ID)
}

func (a *Service) issue(userID int64) (*Tokens, error) {
	access, err := a.signAccess(userID)
	if err != nil {
		return nil, err
	}
	refresh, hash, err := newRefreshToken()
	if err != nil {
		return nil, err
	}
	if err := a.store.SaveRefreshToken(userID, hash, time.Now().UTC().Add(7*24*time.Hour)); err != nil {
		return nil, err
	}
	return &Tokens{AccessToken: access, RefreshToken: refresh}, nil
}

func (a *Service) signAccess(userID int64) (string, error) {
	claims := jwt.MapClaims{
		"sub": userID,
		"exp": time.Now().UTC().Add(15 * time.Minute).Unix(),
		"iat": time.Now().UTC().Unix(),
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(a.secret)
}

func (a *Service) Refresh(refreshToken string) (*Tokens, error) {
	hash := hashToken(refreshToken)
	userID, err := a.store.ValidateRefreshToken(hash)
	if err != nil {
		return nil, err
	}
	// rotation: revoke old, issue new
	if err := a.store.RevokeRefreshToken(hash); err != nil {
		return nil, err
	}
	return a.issue(userID)
}

func (a *Service) ValidateAccess(tokenStr string) (int64, error) {
	t, err := jwt.Parse(tokenStr, func(t *jwt.Token) (interface{}, error) {
		return a.secret, nil
	})
	if err != nil || !t.Valid {
		return 0, errors.New("invalid token")
	}
	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return 0, errors.New("invalid claims")
	}
	sub, ok := claims["sub"].(float64)
	if !ok {
		return 0, errors.New("invalid subject")
	}
	return int64(sub), nil
}

func newRefreshToken() (string, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	raw := hex.EncodeToString(b)
	h := sha256.Sum256([]byte(raw))
	return raw, hex.EncodeToString(h[:]), nil
}

func hashToken(raw string) string {
	h := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(h[:])
}
