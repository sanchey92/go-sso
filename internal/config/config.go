package config

import (
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Server        ServerConfig        `yaml:"server"`
	Database      DatabaseConfig      `yaml:"database"`
	Auth          AuthConfig          `yaml:"auth"`
	Federation    FederationConfig    `yaml:"federation"`
	MFA           MFAConfig           `yaml:"mfa"`
	Security      SecurityConfig      `yaml:"security"`
	Observability ObservabilityConfig `yaml:"observability"`
}

type ServerConfig struct {
	HTTP HTTPServerConfig `yaml:"http"`
	GRPC GRPCServerConfig `yaml:"grpc"`
}

type HTTPServerConfig struct {
	Host         string        `yaml:"host"          env:"SSO_SERVER_HTTP_HOST"          env-default:"0.0.0.0"`
	Port         int           `yaml:"port"          env:"SSO_SERVER_HTTP_PORT"          env-default:"8080"`
	ReadTimeout  time.Duration `yaml:"read_timeout"  env:"SSO_SERVER_HTTP_READ_TIMEOUT"  env-default:"10s"`
	WriteTimeout time.Duration `yaml:"write_timeout" env:"SSO_SERVER_HTTP_WRITE_TIMEOUT" env-default:"30s"`
}

type GRPCServerConfig struct {
	Host string `yaml:"host" env:"SSO_SERVER_GRPC_HOST" env-default:"0.0.0.0"`
	Port int    `yaml:"port" env:"SSO_SERVER_GRPC_PORT" env-default:"9090"`
}

type DatabaseConfig struct {
	Postgres PostgresConfig `yaml:"postgres"`
	Redis    RedisConfig    `yaml:"redis"`
}

type PostgresConfig struct {
	DSN             string        `yaml:"dsn"               env:"SSO_DATABASE_POSTGRES_DSN"               env-required:"true"`
	MaxOpenConns    int           `yaml:"max_open_conns"    env:"SSO_DATABASE_POSTGRES_MAX_OPEN_CONNS"    env-default:"25"`
	MaxIdleConns    int           `yaml:"max_idle_conns"    env:"SSO_DATABASE_POSTGRES_MAX_IDLE_CONNS"    env-default:"10"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime" env:"SSO_DATABASE_POSTGRES_CONN_MAX_LIFETIME" env-default:"5m"`
}

type RedisConfig struct {
	Addr     string `yaml:"addr"     env:"SSO_DATABASE_REDIS_ADDR"     env-default:"localhost:6379"`
	Password string `yaml:"password" env:"SSO_DATABASE_REDIS_PASSWORD" env-default:""`
	DB       int    `yaml:"db"       env:"SSO_DATABASE_REDIS_DB"       env-default:"0"`
}

type AuthConfig struct {
	AccessTokenTTL      time.Duration `yaml:"access_token_ttl"      env:"SSO_AUTH_ACCESS_TOKEN_TTL"      env-default:"15m"`
	RefreshTokenTTL     time.Duration `yaml:"refresh_token_ttl"     env:"SSO_AUTH_REFRESH_TOKEN_TTL"     env-default:"168h"`
	Issuer              string        `yaml:"issuer"                env:"SSO_AUTH_ISSUER"                env-required:"true"`
	JWTSigningAlgorithm string        `yaml:"jwt_signing_algorithm" env:"SSO_AUTH_JWT_SIGNING_ALGORITHM" env-default:"EdDSA"`
}

type OAuthProviderConfig struct {
	ClientID     string `yaml:"client_id"     env-required:"true"`
	ClientSecret string `yaml:"client_secret" env-required:"true"`
	RedirectURL  string `yaml:"redirect_url"  env-required:"true"`
}

type FederationConfig struct {
	Google OAuthProviderConfig `yaml:"google" env-prefix:"SSO_FEDERATION_GOOGLE_"`
	GitHub OAuthProviderConfig `yaml:"github" env-prefix:"SSO_FEDERATION_GITHUB_"`
}

type TOTPConfig struct {
	Issuer string `yaml:"issuer" env:"SSO_MFA_TOTP_ISSUER" env-default:"MySSO"`
	Skew   int    `yaml:"skew"   env:"SSO_MFA_TOTP_SKEW"   env-default:"1"`
}

type MFAConfig struct {
	TOTP TOTPConfig `yaml:"totp"`
}

type RateLimitEntry struct {
	MaxAttempts int           `yaml:"max_attempts"`
	Window      time.Duration `yaml:"window"`
}

type SecurityConfig struct {
	EncryptionKey string          `yaml:"encryption_key" env:"SSO_SECURITY_ENCRYPTION_KEY" env-required:"true"`
	RateLimit     RateLimitConfig `yaml:"rate_limit"`
}

type RateLimitConfig struct {
	Login     RateLimitEntry `yaml:"login"`
	TOTP      RateLimitEntry `yaml:"totp"`
	MagicLink RateLimitEntry `yaml:"magic_link"`
}

type ObservabilityConfig struct {
	Log     LogConfig     `yaml:"log"`
	Metrics MetricsConfig `yaml:"metrics"`
	Tracing TracingConfig `yaml:"tracing"`
}

type LogConfig struct {
	Level  string `yaml:"level"  env:"SSO_LOG_LEVEL"  env-default:"info"`
	Format string `yaml:"format" env:"SSO_LOG_FORMAT" env-default:"json"`
}

type MetricsConfig struct {
	Enabled bool   `yaml:"enabled" env:"SSO_METRICS_ENABLED" env-default:"true"`
	Path    string `yaml:"path"    env:"SSO_METRICS_PATH"    env-default:"/metrics"`
}

type TracingConfig struct {
	Enabled  bool   `yaml:"enabled"  env:"SSO_TRACING_ENABLED"  env-default:"true"`
	Exporter string `yaml:"exporter" env:"SSO_TRACING_EXPORTER" env-default:"otlp"`
	Endpoint string `yaml:"endpoint" env:"SSO_TRACING_ENDPOINT" env-default:"localhost:4317"`
}

func MustLoad(configPath string) *Config {
	var cfg Config

	if err := cleanenv.ReadConfig(configPath, &cfg); err != nil {
		panic("failed to read config: " + err.Error())
	}
	return &cfg
}
