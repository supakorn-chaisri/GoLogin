# GoLogin

Secure login backend in Go 1.27.

## Build & Run

```bash
go build ./...
go run ./cmd/server
```

Server listens on `:8080`.

## Environment Variables

- `JWT_SECRET` — JWT signing secret (default: dev secret, change in production)

## API Endpoints

- `POST /signup` — `{ "email", "password" }` → `{ "id", "email" }`
- `POST /login` — `{ "email", "password" }` → `{ "access_token", "refresh_token" }`
- `POST /refresh` — `{ "refresh_token" }` → `{ "access_token", "refresh_token" }`
- `GET /me` — `Authorization: Bearer <access_token>` → `{ "id", "email", "role" }`

## Tests

```bash
go test ./...
```
EOF