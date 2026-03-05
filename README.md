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
  app/             — use cases + ports
  adapter/driving/ — REST, gRPC
  adapter/driven/  — PostgreSQL, Redis, JWT, Hasher
```

## Status

**Phase 1: Foundation** — in progress

Done: project structure, Taskfile + linter + Docker, config (cleanenv), logging (zap), PostgreSQL (pgx), Redis (go-redis), migrations (goose), domain models, password hasher (argon2id), JWT service (EdDSA), use case Registration, use case Login, refresh token rotation with replay detection.

### Current

- **HTTP server + middleware** — Request ID, Panic Recovery, Structured Logging, CORS

### Roadmap
- REST handlers for auth endpoints
- Email verification
- Password reset flow

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
