FROM golang:1.26-alpine AS builder

RUN apk add --no-cache upx

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o ./bin/sso ./cmd/sso/ \
    && upx --best --lzma ./bin/sso

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /app/bin/sso /sso
COPY --from=builder /app/config /config

EXPOSE 8080 50051 9090

ENTRYPOINT ["/sso"]
