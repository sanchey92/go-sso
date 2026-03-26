# SSO Microservice

Production-ready Single Sign-On сервис на Go — полноценный Identity Provider с нуля.

OAuth 2.0 / OIDC, MFA (TOTP + recovery codes), passwordless (magic links), Federation (Google, GitHub).
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
    errors/           sentinel errors (24 типа)
  usecase/            use cases + port interfaces (рядом с потребителем)
    auth/             Login
    user/             Register, VerifyEmail, ResetPassword, GetUserInfo
    token/            IssueTokenPair, RefreshTokens, RevokeToken
    client/           Create, GetByID, VerifySecret (OAuth clients)
    oauth/            Authorize, ExchangeCode (OAuth 2.0 + PKCE)
    federation/       InitiateOAuth, HandleCallback (Google, GitHub)
    mfa/              SetupTOTP, VerifySetup, VerifyTOTP, VerifyRecoveryCode, DisableTOTP
  adapter/
    driving/rest/     HTTP server (chi), handler sub-packages, middleware
    driven/           PostgreSQL (pgx), Redis, JWT (EdDSA), Argon2id, AES-256-GCM, Email, OAuth providers
pkg/
  crypto/             token generation, SHA-256 hashing, PKCE, UUID
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
| MFA secrets | AES-256-GCM encrypted at rest (random nonce per encryption) |
| Recovery codes | One-time use, bcrypt hashed, 10 codes per user |
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

### MFA (Phase 4 — in progress)
```
POST   /api/v1/auth/mfa/totp/setup          200  Начать TOTP setup (Bearer required)
POST   /api/v1/auth/mfa/totp/verify-setup   200  Подтвердить TOTP → recovery codes
DELETE /api/v1/auth/mfa/totp                 204  Отключить TOTP (code required)
POST   /api/v1/auth/mfa/totp/verify          200  MFA login — TOTP code
POST   /api/v1/auth/mfa/recovery/verify      200  MFA login — recovery code
```

### Passwordless (Phase 4 — planned)
```
POST /api/v1/auth/magic-link/request     200  Запрос magic link (anti-enumeration)
POST /api/v1/auth/magic-link/verify      200  Верификация magic link → tokens
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

E2E тесты: 18 тестов — полный flow Register → Verify Email → Login → OAuth Authorize (PKCE) → Token Exchange → UserInfo → Refresh (rotation) → Revoke. Error cases: replay detection, code reuse, wrong PKCE, RFC 7009 compliance.

### Phase 3: Federation — Done (7/7)

Identity Federation через внешних провайдеров.

- **Google OAuth** — OpenID Connect, scopes: `openid email profile`
- **GitHub OAuth** — scopes: `user:email read:user`, fallback на `/user/emails` для приватных email
- **Auto-provisioning** — новый user создаётся автоматически (без пароля, email_verified=true)
- **Account linking** — совпадение email → привязка к существующему аккаунту
- **State management** — state + PKCE verifier в Redis, TTL 10 мин, consume-on-read
- **Транзакционность** — `LinkIdentityTx`: find identity → find/create user → insert identity (single transaction)

E2E тесты: 9 тестов — auto-provisioning, account linking, repeat login, unknown provider (404), invalid state (400), missing code/state (400), email not verified (403), provider error (400).

**Итого: 27 E2E тестов, полное покрытие OAuth 2.0 + Federation flows.**

### Phase 4: MFA + Passwordless — In Progress (7/12)

MFA инфраструктура, бизнес-логика и auth-интеграция готовы:

- **AES-256-GCM Encryptor** — шифрование TOTP-секретов at rest (random nonce, 32-byte key)
- **Recovery codes** — таблица `recovery_codes` (FK CASCADE на users), PostgreSQL адаптер (SaveCodes batch insert, GetUnusedByUserID, MarkUsed, DeleteByUserID)
- **User MFA update** — `UpdateMFA` в PostgreSQL адаптере (mfa_enabled + mfa_secret_enc)
- **Domain models** — `RecoveryCode`, `MFAChallenge`, `LoginResult` + 7 sentinel errors (ErrMFANotEnabled, ErrMFAAlreadyEnabled, ErrInvalidTOTPCode, ErrInvalidMFAToken, ErrRecoveryCodeNotFound, ErrRecoveryCodeUsed, ErrMagicLinkNotFound)
- **MFA usecase** — полный TOTP lifecycle: SetupTOTP (двухфазный setup), VerifySetup (активация + 10 recovery codes), VerifyTOTP (валидация с skew ±1), VerifyRecoveryCode (bcrypt перебор + MarkUsed), DisableTOTP (fallback TOTP → recovery, обнуление секрета)
- **JWT MFA token** — EdDSA JWT с purpose=mfa_pending (TTL 5 мин), ValidateMFAToken в jwt adapter
- **Auth MFA-aware Login** — Login возвращает `LoginResult{MFAChallenge}` при mfa_enabled, обратная совместимость для пользователей без MFA
- **CompleteMFALogin / CompleteMFARecovery** — второй шаг MFA-логина: валидация MFA-токена → проверка TOTP-кода или recovery code → выпуск токенов
- **Интеграционные тесты** — 5 тестов (8 sub-tests) для recovery codes + MFA update
- **Unit-тесты** — MFA usecase 27 тестов, auth usecase 20 тестов (Login 11 + CompleteMFALogin 4 + CompleteMFARecovery 5), JWT MFA adapter 5 тестов

**Следующие шаги:**

| # | Задача | Описание |
|---|--------|----------|
| TASK-043 | Handler: MFA setup endpoints | POST setup, verify-setup, DELETE disable (Bearer) |
| TASK-044 | Handler: MFA verify + rate limiting | POST totp/verify, recovery/verify (5 req / 5 min) |
| TASK-045 | Magic Link service | RequestMagicLink (anti-enumeration), VerifyMagicLink |
| TASK-046 | Handler: Magic Link endpoints | POST request, verify (3 req / 15 min rate limit) |
| TASK-047 | E2E тесты: MFA + Magic Link | Full TOTP flow, recovery, disable, magic link |

### Phase 5: gRPC + Observability — Planned (0/11)

| Feature | Задачи | Description |
|---------|--------|------------|
| Protobuf + gRPC server | TASK-048, 049 | buf setup, proto definitions, server scaffold |
| gRPC handlers | TASK-050, 051 | IntrospectToken (+ cache), ValidateToken, GetUser, BatchValidate |
| Interceptors | TASK-052 | Auth (API key), Logging, Reflection |
| Prometheus | TASK-053, 054 | HTTP/gRPC metrics middleware, DB/Redis metrics, /metrics endpoint |
| OpenTelemetry | TASK-055, 056 | TracerProvider, HTTP/gRPC/DB/Redis tracing |
| Health checks | TASK-057 | /healthz, /readyz (PG + Redis), gRPC Health service |
| E2E тесты | TASK-058 | gRPC introspection, validation, batch, auth interceptor |

### Phase 6: Hardening — Planned (0/7)

| Feature | Задачи | Description |
|---------|--------|------------|
| Security headers | TASK-059 | X-Content-Type-Options, X-Frame-Options, HSTS, CSP |
| Graceful shutdown | TASK-060 | LIFO: HTTP → gRPC → OTel → Redis → PG |
| Security audit | TASK-061 | gosec, rate limit completeness, TTL audit, secret logging |
| Docker Compose | TASK-062 | Full environment: app + PG + Redis + Prometheus + Jaeger |
| OpenAPI 3.0 | TASK-063 | Full spec for all REST endpoints |
| CI/CD | TASK-064 | GitHub Actions (lint, test, integration, build, docker) |
| README | TASK-065 | Quick Start guide, .env.example |

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

# E2E tests (requires Docker — full OAuth 2.0 + Federation + MFA flows)
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

recovery_codes
├── id (UUID PK)
├── user_id (FK -> users, CASCADE)
├── code_hash (TEXT, bcrypt)
├── used (BOOLEAN, default false)
└── created_at
```

## License

MIT
