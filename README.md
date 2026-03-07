# SSO Microservice

Production-ready Single Sign-On сервис на Go. Identity Provider с OAuth 2.0 / OIDC, MFA (TOTP), passwordless (magic links) и федерацией (Google, GitHub). REST API (public) + gRPC API (internal).

## Tech Stack

Go, PostgreSQL, Redis, JWT (EdDSA), Argon2id, gRPC, Prometheus, OpenTelemetry

## Architecture

Hexagonal (Ports & Adapters) — domain models без внешних зависимостей, use cases определяют интерфейсы (ports), адаптеры реализуют их неявно.

```
cmd/sso/           — entrypoint
internal/
  domain/model/    — бизнес-сущности
  usecase/         — use cases + ports
  adapter/driving/ — REST, gRPC
  adapter/driven/  — PostgreSQL, Redis, JWT, Hasher, Email
```

## Status

**Phase 1: Foundation** — in progress

Done: project structure, Taskfile + linter + Docker, config (cleanenv), logging (zap), PostgreSQL (pgx), Redis (go-redis), migrations (goose), domain models, password hasher (argon2id), JWT service (EdDSA), use case Registration, use case Login, refresh token rotation with replay detection, HTTP server + middleware (chi), REST auth handlers, email verification, password reset flow.

### API Endpoints

| Method | Path | Description | Status |
|--------|------|-------------|--------|
| POST | `/api/v1/auth/register` | Регистрация | 201 |
| POST | `/api/v1/auth/login` | Логин → access + refresh tokens | 200 |
| POST | `/api/v1/auth/token/refresh` | Ротация refresh token | 200 |
| POST | `/api/v1/auth/token/revoke` | Отзыв refresh token | 204 |
| POST | `/api/v1/auth/email/verify` | Верификация email по токену | 200 |
| POST | `/api/v1/auth/password/reset-request` | Запрос сброса пароля | 200 |
| POST | `/api/v1/auth/password/reset` | Сброс пароля по токену | 200 |
| GET | `/healthz` | Health check | 200 |

### Roadmap
- Rate limiting (Redis)
- main.go + DI + graceful shutdown

## Development

```bash
task build   # собрать бинарник
task test    # запустить тесты
task lint    # golangci-lint
task migrate # применить миграции
```

```bash
docker-compose up -d postgres redis   # поднять зависимости
```
