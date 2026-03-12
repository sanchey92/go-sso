# SSO Microservice

Production-ready Single Sign-On сервис на Go — полноценный Identity Provider с нуля.

OAuth 2.0 / OIDC, MFA (TOTP + recovery codes), passwordless (magic links), федерация (Google, GitHub).
REST API (public) + gRPC API (internal). Без фронтенда — чистый бэкенд.

## Why

Большинство проектов используют Auth0 / Keycloak / Firebase Auth. Этот сервис — попытка построить собственный IdP, понимая каждый слой: от хеширования паролей (Argon2id) до replay detection при ротации refresh-токенов.

## Architecture

**Hexagonal (Ports & Adapters)** — бизнес-логика изолирована от инфраструктуры. Все зависимости направлены внутрь.

```
cmd/sso/              entrypoint + DI wiring
internal/
  domain/model/       чистые бизнес-сущности (zero dependencies)
  domain/errors/      sentinel errors
  usecase/            use cases + port interfaces (рядом с потребителем)
    auth/             Login
    user/             Register, VerifyEmail, ResetPassword
    token/            IssueTokenPair, RefreshTokens, RevokeToken
    client/           Create, GetByID, VerifySecret (OAuth clients)
  adapter/
    driving/          входящие: REST (chi), gRPC
    driven/           исходящие: PostgreSQL (pgx), Redis, JWT (EdDSA), Argon2id, Email
pkg/
  crypto/             GenerateRandomToken, HashToken (SHA-256), GenerateUUID
  logger/             zap wrapper
```

**Ключевые принципы:**
- Интерфейсы определяются потребителем, не поставщиком (idiomatic Go)
- Implicit interface satisfaction — адаптеры не импортируют usecase
- Constructor DI, без фреймворков
- Маленькие интерфейсы (1-3 метода, ISP)

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Language | Go 1.26 |
| HTTP Router | chi v5 |
| Database | PostgreSQL 16+ (pgx/v5, connection pool) |
| Cache | Redis 7+ (go-redis/v9) |
| JWT | EdDSA (Ed25519), golang-jwt/v5 |
| Passwords | Argon2id (64MB, 3 iter, 4 threads) |
| Config | cleanenv (YAML + env override) |
| Migrations | goose/v3 |
| Logging | zap (structured, JSON/console) |
| Metrics | Prometheus (planned) |
| Tracing | OpenTelemetry (planned) |
| Linting | golangci-lint (gocritic, gosec, exhaustive, errcheck) |
| Testing | testify + mockery + testcontainers-go |
| Proto | buf |
| Tasks | Taskfile |

## Security

- **Passwords** — Argon2id (memory-hard, GPU-resistant)
- **JWT** — EdDSA (Ed25519), короткий TTL (15 мин access, 7 дней refresh)
- **Refresh token rotation** — family-based replay detection: если использован revoked token, вся семья инвалидируется
- **PKCE** — обязателен для всех OAuth flows (S256)
- **Rate limiting** — Redis sliding window (login: 10 req/15 min per IP)
- **Email enumeration protection** — одинаковые ответы на reset/magic link для существующих и несуществующих email
- **Constant-time comparison** — для токенов и кодов
- **Security headers** — X-Content-Type-Options, X-Frame-Options, HSTS

## API Endpoints

```
POST   /api/v1/auth/register              201  Регистрация
POST   /api/v1/auth/login                 200  Login → access + refresh tokens
POST   /api/v1/auth/token/refresh         200  Ротация refresh token
POST   /api/v1/auth/token/revoke          204  Отзыв refresh token
POST   /api/v1/auth/email/verify          200  Верификация email
POST   /api/v1/auth/password/reset-request 200 Запрос сброса пароля
POST   /api/v1/auth/password/reset        200  Сброс пароля по токену
POST   /api/v1/auth/oauth/clients/        201  Регистрация OAuth-клиента → client_id + client_secret
GET    /api/v1/auth/oauth/clients/{id}    200  Получение OAuth-клиента (без secret)
GET    /healthz                           200  Health check
```

## Phase 1: Foundation — Done

Полный auth flow: регистрация, email verification, логин, refresh token rotation с replay detection, password reset, rate limiting (Redis).

22 из 22 задач выполнены. Unit-тесты (покрытие usecase/auth 100%, token 95.9%, user 92.5%) + интеграционные тесты (testcontainers: PostgreSQL + Redis, 15 тестов).

## Phase 2: OAuth 2.0 + OIDC — Next

Превращение сервиса в полноценный OAuth 2.0 Authorization Server с OIDC.

| Task | Description | Status |
|------|------------|--------|
| TASK-023 | Регистрация OAuth-клиентов (client_id/secret, bcrypt) | done |
| TASK-024 | Authorization Code + PKCE (`/oauth/authorize`) | planned |
| TASK-025 | Token endpoint (code exchange, PKCE verify, refresh grant) | planned |
| TASK-026 | Token revocation (RFC 7009) + OIDC Discovery (`/.well-known/openid-configuration`) | planned |
| TASK-027 | JWKS endpoint (`/.well-known/jwks.json`) + UserInfo | planned |
| TASK-028 | E2E-тесты полного OAuth flow | planned |

**Что это даст:**
- Любое приложение сможет интегрироваться через стандартный OAuth 2.0 / OIDC
- PKCE (S256) обязателен — защита от authorization code interception
- Authorization code одноразовый (TTL 60s, Redis)
- OIDC Discovery — автоматическая конфигурация для клиентов
- JWKS — публичные ключи для верификации JWT без обращения к серверу

## Phases 3-6: Roadmap

| Phase | Focus | Key Features |
|-------|-------|-------------|
| **3. Federation** | Identity Federation | Google OAuth, GitHub OAuth, auto-provisioning, account linking |
| **4. MFA + Passwordless** | Multi-Factor Auth | TOTP (authenticator apps), recovery codes, magic links |
| **5. gRPC + Observability** | Internal API + Monitoring | gRPC server (IntrospectToken, ValidateToken), Prometheus, OpenTelemetry, health checks |
| **6. Hardening** | Production readiness | Full docker-compose env, security audit, OpenAPI 3.0 spec, CI/CD (GitHub Actions) |

## Development

```bash
# Dependencies
docker-compose up -d postgres redis

# Build & run
task build
task run

# Quality
task test                  # unit tests
task test:cover            # unit tests + coverage report in browser
task test:integration      # integration tests (requires Docker)
task lint

# Migrations
task migrate-up
task migrate-down

# Proto (Phase 5)
task proto-gen
```

## Project Structure

```
.
├── cmd/sso/                  entrypoint
├── config/
│   ├── config.local.yaml     dev defaults
│   └── config.production.yaml  prod (env placeholders)
├── internal/
│   ├── app/                  composition root (DI wiring)
│   ├── config/               cleanenv config structs
│   ├── domain/
│   │   ├── model/            User, RefreshToken, OAuthClient, TokenPair
│   │   └── errors/           sentinel errors (11 types)
│   ├── usecase/
│   │   ├── auth/             Login + interfaces
│   │   ├── user/             Register, VerifyEmail, ResetPassword + interfaces
│   │   ├── token/            IssueTokenPair, RefreshTokens, RevokeToken + interfaces
│   │   └── client/           Create, GetByID, VerifySecret (OAuth clients) + interfaces
│   └── adapter/
│       ├── driving/
│       │   └── rest/         HTTP server (chi), handlers, middleware
│       └── driven/
│           ├── postgres/     pgx pool, UserRepo, RefreshTokenRepo, OAuthClientRepo
│           ├── redis/        cache (Set/Get/Delete)
│           ├── jwt/          EdDSA token generator
│           ├── hasher/       Argon2id
│           └── email/        log sender (stub)
├── test/
│   └── integration/          integration tests (testcontainers, //go:build integration)
│       ├── postgres/          UserRepo, RefreshTokenRepo, OAuthClientRepo
│       └── redis/             CacheStore (Set/Get/Delete/TTL)
├── migrations/               SQL (goose)
├── pkg/
│   ├── closer/               graceful shutdown (parallel close, panic recovery, signals)
│   ├── crypto/               token generation, hashing
│   └── logger/               zap wrapper
├── proto/                    Protobuf definitions (Phase 5)
└── deploy/                   deployment configs
```
