# SSO Identity Provider

**Production-ready Single Sign-On microservice built from scratch in Go.**

A full-featured Identity Provider implementing OAuth 2.0, OpenID Connect, Multi-Factor Authentication, passwordless login, and federated identity — without depending on Auth0, Keycloak, or Firebase Auth.

REST API (public) + gRPC API (internal). Pure backend, no frontend.

---

## Highlights

- **Complete OAuth 2.0 + OIDC** — Authorization Code with mandatory PKCE, JWKS with key rotation, Discovery, UserInfo
- **Multi-Factor Authentication** — TOTP (RFC 6238), 10 one-time recovery codes, AES-256-GCM encrypted secrets at rest
- **Federation** — Google & GitHub SSO with auto-provisioning and account linking
- **Passwordless** — Magic link authentication with single-use tokens
- **Refresh Token Rotation** — Family-based with replay detection: compromised token invalidates entire family
- **gRPC Internal API** — Token introspection, validation, user lookup with Redis caching and batch operations
- **Full Observability** — Prometheus metrics (HTTP, gRPC, DB, Redis), OpenTelemetry tracing, structured logging (zap)
- **Security-First** — Argon2id passwords, EdDSA JWT, constant-time comparisons, rate limiting, anti-enumeration
- **Clean Architecture** — Hexagonal (Ports & Adapters), consumer-defined interfaces, constructor DI, zero frameworks
- **44 E2E Tests** — Full flows on real PostgreSQL + Redis via testcontainers

---

## Architecture

**Hexagonal (Ports & Adapters)** — business logic has zero infrastructure dependencies. All dependencies point inward.

```
cmd/sso/                     Entry point
internal/
  app/                       Composition root, DI wiring, graceful shutdown
  config/                    cleanenv (YAML + env override)
  domain/
    model/                   Business entities (User, Token, OAuthClient, MFA, Federation)
    errors/                  24 sentinel errors
  usecase/                   Business logic (8 packages)
    auth/                    Login (MFA-aware)
    user/                    Register, VerifyEmail, ResetPassword
    token/                   IssueTokenPair, Refresh (rotation), Revoke
    client/                  OAuth client CRUD
    oauth/                   Authorize + ExchangeCode (PKCE)
    federation/              Google, GitHub (auto-provision + account linking)
    mfa/                     TOTP lifecycle, recovery codes
    magiclink/               Passwordless authentication
  adapter/
    driving/rest/            HTTP server (chi), 14 handler packages, middleware
    driving/grpc/            gRPC server, handler, interceptors (auth, logging, metrics)
    driven/                  PostgreSQL, Redis, JWT, Argon2id, AES-256-GCM, Email, OAuth providers
pkg/                         Shared utilities (crypto, closer, logger, metrics, tracing)
migrations/                  SQL migrations (goose)
proto/                       Protobuf definitions
test/e2e/                    44 E2E tests (testcontainers)
```

**Design principles:**
- Interfaces defined by consumer, not provider (idiomatic Go)
- Implicit interface satisfaction — adapters don't import usecases
- Small interfaces (1-3 methods, ISP)
- Constructor DI, no frameworks or code generation for wiring
- Decentralized error handling — each handler maps domain errors independently

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Go 1.26 |
| HTTP | go-chi/chi v5 |
| gRPC | google.golang.org/grpc, buf (proto generation) |
| Database | PostgreSQL 17 (pgx/v5, connection pooling) |
| Cache | Redis 7+ (go-redis/v9) |
| JWT | EdDSA (Ed25519), golang-jwt/v5, JWKS key rotation |
| Passwords | Argon2id (64 MB, 3 iterations, 4 threads) |
| Encryption | AES-256-GCM (TOTP secrets at rest) |
| Config | cleanenv (YAML + env override) |
| Migrations | goose/v3 |
| Logging | zap (structured JSON / console) |
| Metrics | Prometheus (HTTP, gRPC, DB, Redis, Auth) |
| Tracing | OpenTelemetry (OTLP gRPC exporter, W3C propagation) |
| Linting | golangci-lint v2 (gocritic, gosec, exhaustive, errcheck) |
| Testing | testify + mockery + testcontainers-go |
| DevOps | Docker, docker-compose, Taskfile |

---

## Security

| Feature | Implementation |
|---------|----------------|
| Password hashing | Argon2id (memory-hard, 64 MB, GPU-resistant) |
| JWT signing | EdDSA (Ed25519) with JWKS key rotation |
| Token TTL | Access: 15 min, Refresh: 7 days, MFA: 5 min |
| OAuth PKCE | Mandatory S256 for all authorization flows |
| MFA secrets | AES-256-GCM encrypted at rest (random nonce) |
| Recovery codes | 10 per user, one-time use, bcrypt hashed |
| Refresh rotation | Family-based with replay detection |
| Rate limiting | Redis sliding window — login: 10/15min, MFA: 5/5min, magic link: 3/15min per IP |
| gRPC auth | x-api-key (constant-time comparison), health check bypass |
| Anti-enumeration | Identical responses for existing/nonexistent emails |
| Constant-time | All token and code comparisons via `subtle.ConstantTimeCompare` |
| Security headers | X-Content-Type-Options, X-Frame-Options, HSTS |

---

## API Reference

### Authentication

```
POST /api/v1/auth/register               201  Register new user
POST /api/v1/auth/login                   200  Login -> access + refresh tokens (MFA-aware)
POST /api/v1/auth/token/refresh           200  Refresh token rotation
POST /api/v1/auth/token/revoke            204  Revoke refresh token
POST /api/v1/auth/email/verify            200  Verify email by token
POST /api/v1/auth/password/reset-request  200  Request password reset
POST /api/v1/auth/password/reset          200  Reset password by token
```

### OAuth 2.0 / OIDC

```
GET  /api/v1/oauth/authorize              302  Authorization Code + PKCE (S256)
POST /api/v1/oauth/token                  200  Token endpoint (code exchange, refresh grant)
POST /api/v1/oauth/revoke                 200  Token revocation (RFC 7009)
POST /api/v1/oauth/userinfo               200  UserInfo (RFC 6750 Bearer token)
POST /api/v1/oauth/clients/               201  Register OAuth client
GET  /api/v1/oauth/clients/{id}           200  Get OAuth client info
```

### Federation

```
GET  /api/v1/federation/{provider}/authorize  302  Redirect to identity provider
GET  /api/v1/federation/{provider}/callback   200  Handle callback -> tokens
```

Supported providers: **Google** (OpenID Connect) and **GitHub** (OAuth 2.0 with email fallback).

### Multi-Factor Authentication

```
POST   /api/v1/auth/mfa/totp/setup          200  Start TOTP setup (Bearer required)
POST   /api/v1/auth/mfa/totp/verify-setup   200  Confirm TOTP -> recovery codes
DELETE /api/v1/auth/mfa/totp                 204  Disable TOTP
POST   /api/v1/auth/mfa/totp/verify          200  MFA login with TOTP code
POST   /api/v1/auth/mfa/recovery/verify      200  MFA login with recovery code
```

### Passwordless

```
POST /api/v1/auth/magic-link/request     200  Request magic link (anti-enumeration)
POST /api/v1/auth/magic-link/verify      200  Verify magic link -> tokens
```

### Discovery & Health

```
GET  /.well-known/openid-configuration   200  OIDC Discovery document
GET  /.well-known/jwks.json              200  JWKS (EdDSA public keys)
GET  /healthz                            200  Liveness probe
GET  /readyz                             200  Readiness probe (PG + Redis)
```

### gRPC Internal API

Service-to-service API protected by `x-api-key` header. Not for external clients.

```protobuf
service SSOInternalService {
  rpc IntrospectToken(...)      // Token -> active, subject, issuer, expires_at (Redis cache)
  rpc ValidateToken(...)        // Token -> valid, user_id, email, email_verified
  rpc GetUser(...)              // user_id -> full user profile
  rpc BatchValidateTokens(...)  // Parallel validation (errgroup, limit 10)
}
```

gRPC Health Check (`grpc.health.v1.Health`) with periodic background probes.

---

## Observability

### Metrics (Prometheus)

| Group | Metrics |
|-------|---------|
| HTTP | `http_requests_total` (method, path, status), `http_request_duration_seconds` |
| gRPC | `grpc_requests_total` (method, status), `grpc_request_duration_seconds` |
| Auth | `auth_login_total` (method, status), `auth_token_issued_total` (type), `auth_mfa_verification_total` |
| Database | `db_query_duration_seconds` (operation: select/insert/update/delete) |
| Redis | `redis_operation_duration_seconds` (operation) |

### Tracing (OpenTelemetry)

- OTLP gRPC exporter (Jaeger, Grafana Tempo, etc.)
- Parent-based sampling with configurable rate
- Full trace propagation: HTTP request -> usecase -> DB/Redis spans
- W3C Trace Context and Baggage propagation

### Logging (zap)

- Structured JSON output (production) or console (development)
- Request ID propagation via `X-Request-ID` header
- Panic recovery with stack trace logging
- Per-request logging: method, path, status, duration

---

## Database Schema

```
users                         oauth_clients
 id (UUID PK)                  id (UUID PK)
 email (UNIQUE)                name
 password_hash (nullable)      secret_hash (bcrypt)
 email_verified                redirect_uris (TEXT[])
 mfa_enabled                   allowed_scopes (TEXT[])
 mfa_secret_enc (AES-256)      is_confidential
 status                        created_at
 created_at, updated_at

refresh_tokens                federated_identities
 id (UUID PK)                  id (UUID PK)
 token_hash (SHA-256)          user_id (FK -> users)
 user_id (FK -> users)         provider (google|github)
 client_id (FK, nullable)      provider_user_id
 family_id (replay detect)     email, name, avatar_url
 scopes, expires_at            UNIQUE (provider, provider_user_id)
 revoked, created_at           created_at, updated_at

recovery_codes
 id (UUID PK)
 user_id (FK -> users)
 code_hash (bcrypt)
 used (boolean)
 created_at
```

---

## Quick Start

### Prerequisites

- Go 1.26+
- Docker & Docker Compose
- [Task](https://taskfile.dev/)

### Docker Compose (full environment with observability)

One command to start everything — SSO app, PostgreSQL, Redis, Prometheus, Jaeger:

```bash
task compose-up
```

This starts 6 containers:

| Service | URL | Description |
|---------|-----|-------------|
| SSO REST API | `http://localhost:8080` | Public REST API |
| SSO gRPC | `localhost:50051` | Internal gRPC API |
| Prometheus metrics | `http://localhost:9090/metrics` | Raw metrics endpoint |
| Prometheus UI | `http://localhost:9091` | Metrics dashboard, target status |
| Jaeger UI | `http://localhost:16686` | Distributed tracing |

Migrations run automatically via init container before the app starts.

Verify everything is working:

```bash
# Liveness
curl localhost:8080/healthz
# {"status":"ok"}

# Readiness (checks Postgres + Redis)
curl localhost:8080/readyz
# {"checks":{"postgres":"ok","redis":"ok"},"status":"ready"}

# Prometheus metrics
curl localhost:9090/metrics | grep sso_

# Register a user
curl -X POST localhost:8080/api/v1/auth/register \
  -H 'Content-Type: application/json' \
  -d '{"email":"test@test.com","password":"Test1234!"}'
```

After making requests, check:
- **Prometheus UI** (`localhost:9091`) — Targets page shows `sso` with status **UP**
- **Jaeger UI** (`localhost:16686`) — Select service `sso` to see request traces

Manage the environment:

```bash
task compose-logs    # Tail SSO app logs
task compose-down    # Stop all services
```

### Run locally (without Docker)

```bash
# Start only Postgres and Redis
task dev:up

# Install tools
task install:tools

# Run migrations + start app
task dev:start
```

### Testing

```bash
task test                # Unit tests
task test:cover          # Coverage report (opens in browser)
task test:integration    # Integration tests (testcontainers)
task test:e2e            # E2E tests — full OAuth, Federation, MFA, gRPC flows
```

### Code Quality

```bash
task lint                # golangci-lint (gocritic, gosec, exhaustive, errcheck)
task format              # gofumpt + gci
task mockery:gen         # Generate mocks
```

### Migrations

```bash
task migrate:up                        # Apply all pending
task migrate:down                      # Rollback last
task migrate:status                    # Show current state
task migrate:create -- add_new_table   # Create new migration
```

---

## Configuration

Config loaded via cleanenv: YAML base + environment variable override.

| File | Purpose |
|------|---------|
| `config/config.local.yaml` | Development defaults |
| `config/config.production.yaml` | Production (all secrets via env) |
| `.env` | Environment variable overrides |

Key environment variables:

```bash
SSO_DATABASE_POSTGRES_DSN=postgres://user:pass@localhost:5432/sso?sslmode=disable
SSO_DATABASE_REDIS_ADDR=localhost:6379
SSO_AUTH_ISSUER=https://sso.example.com
SSO_SECURITY_ENCRYPTION_KEY=your-32-byte-encryption-key!!!
SSO_SERVER_GRPC_API_KEY=your-grpc-api-key
SSO_FEDERATION_GOOGLE_CLIENT_ID=...
SSO_FEDERATION_GOOGLE_CLIENT_SECRET=...
SSO_FEDERATION_GITHUB_CLIENT_ID=...
SSO_FEDERATION_GITHUB_CLIENT_SECRET=...
```

---

## Test Coverage

**44 E2E tests** running against real PostgreSQL and Redis (testcontainers):

| Area | Tests | What's covered |
|------|-------|----------------|
| Auth | 5 | Register, login, email verification, password reset, error cases |
| OAuth 2.0 | 8 | Full PKCE flow, token exchange, refresh rotation, revocation (RFC 7009) |
| Federation | 9 | Google auto-provisioning, account linking, repeat login, error cases |
| MFA | 8 | TOTP setup/verify/disable, recovery codes, error scenarios |
| Magic Link | 3 | Full flow, anti-enumeration, invalid token |
| gRPC | 7 | Introspection (+ cache), validation, GetUser, batch, auth interceptor, health |
| Discovery | 3 | OIDC config, JWKS, health check |
| UserInfo | 4 | Valid token, missing/invalid token |

Unit tests cover all use cases, handlers, and middleware with mockery-generated mocks.

---

## License

MIT
