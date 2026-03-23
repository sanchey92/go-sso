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
    oauth/            Authorize, ExchangeCode, RefreshTokens (OAuth 2.0 + PKCE)
    federation/       InitiateOAuth, HandleCallback (Google, GitHub)
  adapter/
    driving/          входящие: REST (chi), gRPC
    driven/           исходящие: PostgreSQL (pgx), Redis, JWT (EdDSA), Argon2id, Email
pkg/
  crypto/             GenerateRandomToken, HashToken (SHA-256), GenerateUUID
  closer/             graceful shutdown (parallel close, panic recovery, signals)
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
POST   /api/v1/auth/register               201  Регистрация
POST   /api/v1/auth/login                  200  Login → access + refresh tokens
POST   /api/v1/auth/token/refresh          200  Ротация refresh token
POST   /api/v1/auth/token/revoke           204  Отзыв refresh token (internal)
POST   /api/v1/auth/email/verify           200  Верификация email
POST   /api/v1/auth/password/reset-request 200  Запрос сброса пароля
POST   /api/v1/auth/password/reset         200  Сброс пароля по токену
GET    /api/v1/oauth/authorize             302  OAuth 2.0 Authorization Code + PKCE
POST   /api/v1/oauth/token                200  Token endpoint (code exchange, refresh grant)
POST   /api/v1/oauth/revoke               200  Token revocation (RFC 7009, always 200)
POST   /api/v1/oauth/userinfo              200  UserInfo (Bearer token → sub, email, email_verified)
POST   /api/v1/oauth/clients/              201  Регистрация OAuth-клиента → client_id + client_secret
GET    /api/v1/oauth/clients/{id}          200  Получение OAuth-клиента (без secret)
GET    /.well-known/openid-configuration   200  OIDC Discovery (issuer, endpoints, scopes)
GET    /.well-known/jwks.json              200  JWKS (EdDSA public keys, key rotation)
GET    /healthz                            200  Health check
```

## Phase 1: Foundation — Done

Полный auth flow: регистрация, email verification, логин, refresh token rotation с replay detection, password reset, rate limiting (Redis).

22 из 22 задач выполнены. Unit-тесты (покрытие usecase/auth 100%, token 95.9%, user 92.5%) + интеграционные тесты (testcontainers: PostgreSQL + Redis, 15 тестов).

## Phase 2: OAuth 2.0 + OIDC — Done

Превращение сервиса в полноценный OAuth 2.0 Authorization Server с OIDC.

| Task | Description | Status |
|------|------------|--------|
| TASK-023 | Регистрация OAuth-клиентов (client_id/secret, bcrypt) | done |
| TASK-024 | Authorization Code + PKCE (`/oauth/authorize`) | done |
| TASK-025 | Token endpoint (code exchange, PKCE verify, refresh grant) | done |
| TASK-026 | Token revocation (RFC 7009) + OIDC Discovery (`/.well-known/openid-configuration`) | done |
| TASK-027 | JWKS endpoint (`/.well-known/jwks.json`) + UserInfo (`/oauth/userinfo`) | done |
| TASK-028 | E2E-тесты полного OAuth flow (18 тестов, testcontainers) | done |

6 из 6 задач выполнены. E2E-тесты покрывают полный flow: Register → Verify Email → Login → OAuth Authorize (PKCE S256) → Token Exchange → UserInfo → Refresh (rotation) → Revoke. Error cases: replay detection, code reuse, wrong PKCE, RFC 7009 compliance.

**Что реализовано:**
- Любое приложение может интегрироваться через стандартный OAuth 2.0 / OIDC
- PKCE (S256) обязателен — защита от authorization code interception
- Authorization code одноразовый (TTL 60s, Redis)
- OIDC Discovery — автоматическая конфигурация для клиентов (issuer, endpoints, scopes, grant_types)
- Token revocation (RFC 7009) — безопасный отзыв refresh tokens
- JWKS — публичные ключи EdDSA для верификации JWT без обращения к серверу, key rotation
- UserInfo — Bearer token → claims (sub, email, email_verified), RFC 6750 WWW-Authenticate headers

## Phase 3: Federation — In Progress

Identity Federation: внешние провайдеры (Google, GitHub), auto-provisioning, account linking.

| Task | Description | Status |
|------|------------|--------|
| TASK-029 | Миграция `federated_identities` (user_id FK, provider, UNIQUE constraint) | done |
| TASK-030 | Интерфейсы федерации + Federation service (InitiateOAuth, HandleCallback) | done |
| TASK-031 | Google OAuth адаптер (IdentityProvider: GetAuthURL, ExchangeCode) | — |
| TASK-032 | GitHub OAuth адаптер (IdentityProvider: GetAuthURL, ExchangeCode) | — |
| TASK-033 | Auto-provisioning + account linking (транзакционный LinkIdentityTx) | done |
| TASK-034 | REST-хендлеры федерации (handler готов, подключение в routes pending) | — |
| TASK-035 | Тесты federation flows | — |

**Что уже реализовано:**
- Federation usecase: `InitiateOAuth` (state + PKCE verifier → Redis, TTL 10 мин) и `HandleCallback` (validate state → exchange code → link identity → issue tokens)
- PostgreSQL: транзакционный `LinkIdentityTx` — auto-provisioning (user без пароля, email_verified=true) + account linking по email + повторный вход
- REST handler: `Authorize` (302 redirect), `Callback` (JSON tokens) — написан и протестирован, но ещё не подключен в роуты
- Интеграционные тесты: 7 тестов (auto-provision, repeat login, account linking, two providers same email, cascade delete)
- 5 новых domain errors: `ErrFederatedIdentityNotFound`, `ErrIdentityAlreadyLinked`, `ErrProviderNotSupported`, `ErrInvalidOAuthState`, `ErrProviderEmailNotVerified`

## Phases 4-6: Roadmap

| Phase | Focus | Key Features |
|-------|-------|-------------|
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
task test:e2e              # e2e tests — full OAuth 2.0 flow (requires Docker)
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
│   │   ├── app.go            App struct, Run(), graceful shutdown (closer)
│   │   └── service_provider.go  newServiceProvider, all init* functions
│   ├── config/               cleanenv config structs
│   ├── domain/
│   │   ├── model/            User, RefreshToken, OAuthClient, AuthorizationCode, TokenPair, UserInfo, FederatedIdentity, ProviderUser
│   │   └── errors/           sentinel errors (16 types)
│   ├── usecase/
│   │   ├── auth/             Login + interfaces
│   │   ├── user/             Register, VerifyEmail, ResetPassword, GetUserInfo + interfaces
│   │   ├── token/            IssueTokenPair, RefreshTokens, RevokeToken + interfaces
│   │   ├── client/           Create, GetByID, VerifySecret (OAuth clients) + interfaces
│   │   ├── oauth/            Authorize, ExchangeCode (OAuth 2.0 + PKCE) + interfaces
│   │   └── federation/       InitiateOAuth, HandleCallback (identity federation) + interfaces
│   └── adapter/
│       ├── driving/
│       │   └── rest/         HTTP server (chi), handlers, middleware
│       │       ├── server.go        Server struct, routes, Start/Stop
│       │       ├── handler/         sub-packages по домену (ISP)
│       │       │   ├── httputil/    общие HTTP-утилиты (DecodeJSON, RespondJSON, RespondError)
│       │       │   ├── auth/        Login handler
│       │       │   ├── user/        Register, VerifyEmail, ResetPassword handlers
│       │       │   ├── token/       Refresh, Revoke handlers
│       │       │   ├── client/      OAuth client CRUD handlers
│       │       │   ├── oauth/       Authorize, Token, Revoke (RFC 7009) handlers
│       │       │   ├── discovery/   OIDC Discovery (/.well-known/openid-configuration)
│       │       │   ├── jwks/        JWKS (/.well-known/jwks.json, EdDSA public keys)
│       │       │   ├── userinfo/    UserInfo (/oauth/userinfo, Bearer token → claims)
│       │       │   └── federation/ Authorize (302 redirect), Callback (JSON tokens)
│       │       └── middleware/      RequestID, Recovery, Logging, CORS, RateLimit
│       └── driven/
│           ├── postgres/     pgx pool, UserRepo, RefreshTokenRepo, OAuthClientRepo, FederatedIdentityRepo
│           ├── redis/        cache (Set/Get/Delete), rate limiter (Allow)
│           ├── jwt/          EdDSA token generator, JWKS, TokenValidator, key rotation
│           ├── hasher/       Argon2id
│           └── email/        log sender (stub)
├── test/
│   ├── e2e/                  E2E tests (testcontainers, //go:build e2e, full OAuth flow)
│   └── integration/          integration tests (testcontainers, //go:build integration)
│       ├── postgres/          UserRepo, RefreshTokenRepo, OAuthClientRepo, FederatedIdentityRepo
│       └── redis/             CacheStore (Set/Get/Delete/TTL)
├── migrations/               SQL (goose)
├── pkg/
│   ├── closer/               graceful shutdown (parallel close, panic recovery, signals)
│   ├── crypto/               token generation, hashing
│   └── logger/               zap wrapper
├── proto/                    Protobuf definitions (Phase 5)
└── deploy/                   deployment configs
```
