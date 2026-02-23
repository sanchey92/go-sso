FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o /app/bin/sso ./cmd/sso/

FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY --from=builder /app/bin/sso .
COPY --from=builder /app/config ./config
COPY --from=builder /app/migrations ./migrations

EXPOSE 8080 9090

ENTRYPOINT ["./sso"]
