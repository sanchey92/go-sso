# SSO Microservice

Production-ready Single Sign-On сервис на Go — полноценный Identity Provider с нуля.

OAuth 2.0 / OIDC, MFA (TOTP + recovery codes), passwordless (magic links), федерация (Google, GitHub).
REST API (public) + gRPC API (internal). Без фронтенда — чистый бэкенд.

## Why

Большинство проектов используют Auth0 / Keycloak / Firebase Auth. Этот сервис — попытка построить собственный IdP, понимая каждый слой: от хеширования паролей (Argon2id) до replay detection при ротации refresh-токенов.

## Architecture

**Hexagonal (Ports & Adapters)** — бизнес-логика изолирована от инфраструктуры. Все зависимости направлены внутрь.

```
cmd/sso/              entrypoint
internal/
  app/                composition root (DI wiring, graceful shutdown)
  config/             cleanenv (YAML + env override)
  domain/
    model/            бизнес-сущности (zero dependencies)
    errors/           sentinel errors (16 типов)
  usecase/            use cases + port interfaces (рядом с потребителем)
    auth/             Login
    user/             Register, VerifyEmail, ResetPassword, GetUserInfo
    token/            IssueTokenPair, RefreshTokens, RevokeToken
    client/           Create, GetByID, VerifySecret (OAuth clients)
    oauth/            Authorize, ExchangeCode (OAuth 2.0 + PKCE)
    federation/       InitiateOAuth, HandleCallback (Google, GitHub)
  adapter/
    driving/rest/     HTTP server (chi), handler sub-packages, middleware
    driven/           PostgreSQL (pgx), Redis, JWT (EdDSA), Argon2id, Email, OAuth providers
pkg/
  crypto/             token generation, SHA-256 hashing, PKCE
  closer/             graceful shutdown (parallel close, panic recovery, signals)
  logger/             zap wrapper
test/
  e2e/                E2E tests (27 тестов, testcontainers)
  integration/        integration tests (testcontainers)
migrations/           SQL (goose)
proto/                Protobuf definitions (Phase 5)
```

**Ключевые принципы:**
- Интерфейсы определяются потребителем, не поставщиком (idiomatic Go)
- Implicit interface satisfaction — адаптеры не импортируют usecase
- Constructor DI, без фреймворков
- Маленькие интерфейсы (1–3 метода, ISP)
- Decentralized error handling — каждый handler маппит domain errors в HTTP самостоятельно

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Go 1.26 |
| HTTP Router | go-chi/chi v5 |
| Database | PostgreSQL 17 (pgx/v5, connection pool) |
| Cache | Redis 7+ (go-redis/v9) |
| JWT | EdDSA (Ed25519), golang-jwt/v5, key rotation |
| Passwords | Argon2id (64 MB, 3 iter, 4 threads) |
| Config | cleanenv (YAML + env override) |
| Migrations | goose/v3 |
| Logging | zap (structured, JSON / console) |
| Metrics | Prometheus (planned) |
| Tracing | OpenTelemetry (planned) |
| Linting | golangci-lint v2 (gocritic, gosec, exhaustive, errcheck) |
| Testing | testify + mockery + testcontainers-go |
| Proto | buf |
| Tasks | Taskfile |
| Containers | Docker, docker-compose |

## Security

| Feature | Details |
|---------|---------|
| Passwords | Argon2id (memory-hard, GPU-resistant), constant-time comparison |
| JWT | EdDSA (Ed25519), short TTL (15 min access, 7 days refresh), key rotation via JWKS |
| Refresh tokens | Family-based rotation + replay detection: revoked token invalidates entire family |
| PKCE | Mandatory S256 for all OAuth flows |
| Federation | State + PKCE verifier in Redis (TTL 10 min), consume-on-read |
| Rate limiting | Redis sliding window (login: 10 req / 15 min per IP) |
| Anti-enumeration | Identical responses for existing / nonexistent emails on reset and magic links |
| Constant-time | All token and code comparisons via `subtle.ConstantTimeCompare` |
| Headers | X-Content-Type-Options, X-Frame-Options, HSTS |

## API

### Auth
```
POST /api/v1/auth/register               201  Регистрация
POST /api/v1/auth/login                   200  Login -> access + refresh tokens
POST /api/v1/auth/token/refresh           200  Ротация refresh token
POST /api/v1/auth/token/revoke            204  Отзыв refresh token
POST /api/v1/auth/email/verify            200  Верификация email по токену
POST /api/v1/auth/password/reset-request  200  Запрос сброса пароля
POST /api/v1/auth/password/reset          200  Сброс пароля по токену
```

### OAuth 2.0 / OIDC
```
GET  /api/v1/oauth/authorize              302  Authorization Code + PKCE (S256)
POST /api/v1/oauth/token                  200  Token endpoint (code exchange, refresh grant)
POST /api/v1/oauth/revoke                 200  Token revocation (RFC 7009, always 200)
POST /api/v1/oauth/userinfo               200  UserInfo (Bearer token -> sub, email, email_verified)
POST /api/v1/oauth/clients/               201  Регистрация OAuth-клиента
GET  /api/v1/oauth/clients/{id}           200  Получение OAuth-клиента (без secret)
```

### Federation (Identity Providers)
```
GET  /api/v1/federation/{provider}/authorize  302  Redirect to provider (Google, GitHub)
GET  /api/v1/federation/{provider}/callback   200  Exchange code -> auto-provision / link -> tokens
```

### Well-Known
```
GET  /.well-known/openid-configuration    200  OIDC Discovery
GET  /.well-known/jwks.json               200  JWKS (EdDSA public keys)
GET  /healthz                             200  Health check
```

## Progress

### Phase 1: Foundation — Done (22/22)

Полный auth flow: регистрация, email verification, логин, refresh token rotation с replay detection, password reset, rate limiting (Redis). Graceful shutdown, structured logging, middleware (RequestID, Recovery, Logging, CORS, RateLimit).

Unit-тесты: покрытие usecase/auth 100%, token 95.9%, user 92.5%. Интеграционные тесты: testcontainers (PostgreSQL + Redis), 15 тестов.

### Phase 2: OAuth 2.0 + OIDC — Done (6/6)

OAuth 2.0 Authorization Server с OIDC Discovery. Authorization Code + PKCE (S256), token endpoint (code exchange, refresh grant), token revocation (RFC 7009), JWKS с key rotation, UserInfo (RFC 6750). OAuth client registration (client_id / bcrypt secret).

E2E тесты: 18 тестов — полный flow Register -> Verify Email -> Login -> OAuth Authorize (PKCE) -> Token Exchange -> UserInfo -> Refresh (rotation) -> Revoke. Error cases: replay detection, code reuse, wrong PKCE, RFC 7009 compliance.

### Phase 3: Federation — Done (7/7)

Identity Federation через внешних провайдеров.

- **Google OAuth** — OpenID Connect, scopes: `openid email profile`
- **GitHub OAuth** — scopes: `user:email read:user`, fallback на `/user/emails` для приватных email
- **Auto-provisioning** — новый user создаётся автоматически (без пароля, email_verified=true)
- **Account linking** — совпадение email -> привязка к существующему аккаунту
- **State management** — state + PKCE verifier в Redis, TTL 10 мин, consume-on-read
- **Транзакционность** — `LinkIdentityTx`: find identity -> find/create user -> insert identity (single transaction)

E2E тесты: 9 тестов — auto-provisioning, account linking, repeat login, unknown provider (404), invalid state (400), missing code/state (400), email not verified (403), provider error (400).

**Итого: 27 E2E тестов, полное покрытие OAuth 2.0 + Federation flows.**

### Phase 4: MFA + Passwordless — Next

| Feature | Description |
|---------|------------|
| TOTP | Authenticator apps (Google Auth, Authy), AES-256-GCM encrypted secrets |
| Recovery codes | One-time backup codes, bcrypt hashed |
| Magic links | Passwordless login via email |

### Phase 5: gRPC + Observability

| Feature | Description |
|---------|------------|
| gRPC API | IntrospectToken, ValidateToken (internal services) |
| Prometheus | HTTP/gRPC metrics, token operations counters |
| OpenTelemetry | Distributed tracing across services |
| Health checks | Liveness + readiness probes |

### Phase 6: Hardening

| Feature | Description |
|---------|------------|
| Docker | Full docker-compose environment |
| Security audit | OWASP top 10 review |
| OpenAPI 3.0 | Full API spec + Swagger UI |
| CI/CD | GitHub Actions (lint, test, build, deploy) |

## Development

### Prerequisites

- Go 1.26+
- Docker & Docker Compose
- [Task](https://taskfile.dev/) (task runner)

### Quick Start

```bash
# Start infrastructure
docker-compose up -d postgres redis

# Install tools
task install:tools

# Run migrations
task migrate:up

# Build & run
task run
```

### Testing

```bash
# Unit tests
task test

# Unit tests + coverage report (opens in browser)
task test:cover

# Integration tests (requires Docker — spins up PostgreSQL + Redis via testcontainers)
task test:integration

# E2E tests (requires Docker — full OAuth 2.0 + Federation flow)
task test:e2e
```

### Quality

```bash
# Lint
task lint

# Format (gofumpt + gci)
task format

# Generate mocks
task mockery:gen
```

### Migrations

```bash
task migrate:up                          # apply all pending
task migrate:down                        # rollback last
task migrate:status                      # show current state
task migrate:create -- add_new_table     # create new migration
```

### Configuration

Config loaded via cleanenv: YAML base + env variable override.

| File | Purpose |
|------|---------|
| `config/config.local.yaml` | Dev defaults (all values filled) |
| `config/config.production.yaml` | Prod (placeholders, secrets via env) |
| `.env` | Local env variables (loaded via godotenv) |

Key env variables:

```bash
SSO_DATABASE_POSTGRES_DSN=postgres://user:pass@localhost:5432/sso?sslmode=disable
SSO_DATABASE_REDIS_ADDR=localhost:6379
SSO_AUTH_ISSUER=https://sso.example.com
SSO_AUTH_ACCESS_TOKEN_TTL=15m
SSO_AUTH_REFRESH_TOKEN_TTL=168h
SSO_SECURITY_ENCRYPTION_KEY=your-32-byte-key
SSO_FEDERATION_GOOGLE_CLIENT_ID=...
SSO_FEDERATION_GOOGLE_CLIENT_SECRET=...
SSO_FEDERATION_GOOGLE_REDIRECT_URL=https://sso.example.com/api/v1/federation/google/callback
SSO_FEDERATION_GITHUB_CLIENT_ID=...
SSO_FEDERATION_GITHUB_CLIENT_SECRET=...
SSO_FEDERATION_GITHUB_REDIRECT_URL=https://sso.example.com/api/v1/federation/github/callback
```

## Database Schema

```sql
users
├── id (UUID PK)
├── email (UNIQUE, CHECK lower)
├── password_hash (nullable — federation users)
├── email_verified
├── mfa_enabled
├── mfa_secret_enc
├── status (active | blocked | deleted)
├── created_at
└── updated_at

oauth_clients
├── id (UUID PK)
├── name
├── secret_hash (bcrypt)
├── redirect_uris (TEXT[])
├── allowed_scopes (TEXT[])
├── is_confidential
└── created_at

refresh_tokens
├── id (UUID PK)
├── token_hash (SHA-256, UNIQUE)
├── user_id (FK -> users)
├── client_id (FK -> oauth_clients, nullable)
├── family_id (UUID — replay detection)
├── scopes (TEXT[])
├── expires_at
├── revoked
└── created_at

federated_identities
├── id (UUID PK)
├── user_id (FK -> users, CASCADE)
├── provider
├── provider_user_id
├── email
├── name
├── avatar_url
├── created_at
├── updated_at
└── UNIQUE (provider, provider_user_id)
```

## License

MIT
