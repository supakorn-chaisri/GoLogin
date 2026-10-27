package store

import (
	"database/sql"
	"errors"
	"time"

	_ "modernc.org/sqlite"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID           int64
	Email        string
	PasswordHash string
	Role         string
	CreatedAt    time.Time
}

type Store struct {
	db *sql.DB
}

func New(path string) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		email TEXT UNIQUE NOT NULL,
		password_hash TEXT NOT NULL,
		role TEXT NOT NULL DEFAULT 'user',
		created_at DATETIME NOT NULL
	);
	CREATE TABLE IF NOT EXISTS refresh_tokens (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		token_hash TEXT UNIQUE NOT NULL,
		expires_at DATETIME NOT NULL,
		revoked INTEGER NOT NULL DEFAULT 0,
		FOREIGN KEY(user_id) REFERENCES users(id)
	);
	`)
	return err
}

func (s *Store) CreateUser(email, password string) (*User, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, err
	}
	res, err := s.db.Exec(`INSERT INTO users(email,password_hash,role,created_at) VALUES(?,?,?,?)`,
		email, string(hash), "user", time.Now().UTC())
	if err != nil {
		return nil, err
	}
	id, _ := res.LastInsertId()
	return &User{ID: id, Email: email, PasswordHash: string(hash), Role: "user", CreatedAt: time.Now().UTC()}, nil
}

func (s *Store) GetUserByEmail(email string) (*User, error) {
	u := &User{}
	err := s.db.QueryRow(`SELECT id,email,password_hash,role,created_at FROM users WHERE email=?`, email).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) GetUserByID(id int64) (*User, error) {
	u := &User{}
	err := s.db.QueryRow(`SELECT id,email,password_hash,role,created_at FROM users WHERE id=?`, id).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (s *Store) CheckPassword(u *User, password string) bool {
	return bcrypt.CompareHashAndPassword([]byte(u.PasswordHash), []byte(password)) == nil
}

func (s *Store) SaveRefreshToken(userID int64, tokenHash string, expires time.Time) error {
	_, err := s.db.Exec(`INSERT INTO refresh_tokens(user_id,token_hash,expires_at) VALUES(?,?,?)`,
		userID, tokenHash, expires)
	return err
}

func (s *Store) RevokeRefreshToken(tokenHash string) error {
	_, err := s.db.Exec(`UPDATE refresh_tokens SET revoked=1 WHERE token_hash=?`, tokenHash)
	return err
}

func (s *Store) ValidateRefreshToken(tokenHash string) (int64, error) {
	var userID int64
	var expires time.Time
	var revoked int
	err := s.db.QueryRow(`SELECT user_id,expires_at,revoked FROM refresh_tokens WHERE token_hash=?`, tokenHash).
		Scan(&userID, &expires, &revoked)
	if err != nil {
		return 0, err
	}
	if revoked == 1 {
		return 0, errors.New("revoked")
	}
	if time.Now().UTC().After(expires) {
		return 0, errors.New("expired")
	}
	return userID, nil
}

func (s *Store) Close() error { return s.db.Close() }
