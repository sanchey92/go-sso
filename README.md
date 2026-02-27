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

Done: project structure, Taskfile + linter + Docker, config (cleanenv), logging (zap), PostgreSQL (pgx), Redis (go-redis), migrations (goose), domain models, password hasher (argon2id).

### Current

- **JWT Service (EdDSA)** — генерация и валидация access tokens с подписью Ed25519, поддержка ротации ключей, JWKS endpoint

### Roadmap

- **Use case: Registration** — `Register(email, password)` с валидацией, хешированием и сохранением в БД
- **Use case: Login** — `Login(email, password)` с выдачей JWT access + refresh token pair
- **Refresh Token Rotation** — ротация refresh tokens с family-based replay detection

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
