package config

import (
	"time"

	"github.com/ilyakaznacheev/cleanenv"
)

type Config struct {
	Server        ServerConfig        `yaml:"server"`
	Database      DatabaseConfig      `yaml:"database"`
	Auth          AuthConfig          `yaml:"auth"`
	OAuth         OAuthConfig         `yaml:"oauth"`
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
	Host            string        `yaml:"host"             env:"SSO_SERVER_HTTP_HOST"             env-default:"0.0.0.0"`
	Port            int           `yaml:"port"             env:"SSO_SERVER_HTTP_PORT"             env-default:"8080"`
	ReadTimeout     time.Duration `yaml:"read_timeout"     env:"SSO_SERVER_HTTP_READ_TIMEOUT"     env-default:"10s"`
	WriteTimeout    time.Duration `yaml:"write_timeout"    env:"SSO_SERVER_HTTP_WRITE_TIMEOUT"    env-default:"30s"`
	ShutdownTimeout time.Duration `yaml:"shutdown_timeout" env:"SSO_SERVER_HTTP_SHUTDOWN_TIMEOUT" env-default:"10s"`
	BaseURL         string        `yaml:"base_url"         env:"SSO_SERVER_HTTP_BASE_URL"         env-default:"http://localhost:8080"`
	MaxBodySize     int64         `yaml:"max_body_size"    env:"SSO_SERVER_HTTP_MAX_BODY_SIZE"    env-default:"1048576"`
}

type GRPCServerConfig struct {
	Host   string `yaml:"host"    env:"SSO_SERVER_GRPC_HOST"    env-default:"0.0.0.0"`
	Port   int    `yaml:"port"    env:"SSO_SERVER_GRPC_PORT"    env-default:"9090"`
	APIKey string `yaml:"api_key" env:"SSO_SERVER_GRPC_API_KEY" env-required:"true"`
}

type DatabaseConfig struct {
	Postgres PostgresConfig `yaml:"postgres"`
	Redis    RedisConfig    `yaml:"redis"`
}

type PostgresConfig struct {
	DSN             string        `yaml:"dsn"                env:"SSO_DATABASE_POSTGRES_DSN"                env-required:"true"`
	MaxConns        int32         `yaml:"max_conns"          env:"SSO_DATABASE_POSTGRES_MAX_CONNS"          env-default:"25"`
	MinConns        int32         `yaml:"min_conns"          env:"SSO_DATABASE_POSTGRES_MIN_CONNS"          env-default:"5"`
	MaxConnLifetime time.Duration `yaml:"max_conn_lifetime"  env:"SSO_DATABASE_POSTGRES_MAX_CONN_LIFETIME"  env-default:"30m"`
	MaxConnIdleTime time.Duration `yaml:"max_conn_idle_time" env:"SSO_DATABASE_POSTGRES_MAX_CONN_IDLE_TIME" env-default:"5m"`
}

type RedisConfig struct {
	Addr            string        `yaml:"addr"               env:"SSO_DATABASE_REDIS_ADDR"               env-default:"localhost:6379"`
	Password        string        `yaml:"password"           env:"SSO_DATABASE_REDIS_PASSWORD"           env-default:""`
	DB              int           `yaml:"db"                 env:"SSO_DATABASE_REDIS_DB"                 env-default:"0"`
	DialTimeout     time.Duration `yaml:"dial_timeout"       env:"SSO_DATABASE_REDIS_DIAL_TIMEOUT"       env-default:"5s"`
	ReadTimeout     time.Duration `yaml:"read_timeout"       env:"SSO_DATABASE_REDIS_READ_TIMEOUT"       env-default:"3s"`
	WriteTimeout    time.Duration `yaml:"write_timeout"      env:"SSO_DATABASE_REDIS_WRITE_TIMEOUT"      env-default:"3s"`
	PoolSize        int           `yaml:"pool_size"          env:"SSO_DATABASE_REDIS_POOL_SIZE"          env-default:"10"`
	MinIdleConns    int           `yaml:"min_idle_conns"     env:"SSO_DATABASE_REDIS_MIN_IDLE_CONNS"     env-default:"2"`
	ConnMaxIdleTime time.Duration `yaml:"conn_max_idle_time" env:"SSO_DATABASE_REDIS_CONN_MAX_IDLE_TIME" env-default:"30m"`
}

type AuthConfig struct {
	AccessTokenTTL      time.Duration `yaml:"access_token_ttl"      env:"SSO_AUTH_ACCESS_TOKEN_TTL"      env-default:"15m"`
	RefreshTokenTTL     time.Duration `yaml:"refresh_token_ttl"     env:"SSO_AUTH_REFRESH_TOKEN_TTL"     env-default:"168h"`
	MFATokenTTL         time.Duration `yaml:"mfa_token_ttl"         env:"SSO_AUTH_MFA_TOKEN_TTL"         env-default:"5m"`
	MagicLinkTTL        time.Duration `yaml:"magic_link_ttl"        env:"SSO_AUTH_MAGIC_LINK_TTL"        env-default:"15m"`
	Issuer              string        `yaml:"issuer"                env:"SSO_AUTH_ISSUER"                env-required:"true"`
	Audience            string        `yaml:"audience"              env:"SSO_AUTH_AUDIENCE"              env-default:"sso"`
	JWTSigningAlgorithm string        `yaml:"jwt_signing_algorithm" env:"SSO_AUTH_JWT_SIGNING_ALGORITHM" env-default:"EdDSA"`
	VerificationTTL     time.Duration `yaml:"verification_ttl"      env:"SSO_AUTH_VERIFICATION_TTL"      env-default:"24h"`
	ResetTTL            time.Duration `yaml:"reset_ttl"             env:"SSO_AUTH_RESET_TTL"             env-default:"1h"`
}

type OAuthConfig struct {
	AuthCodeTTL time.Duration `yaml:"auth_code_ttl" env:"SSO_OAUTH_AUTH_CODE_TTL" env-default:"60s"`
}

type OAuthProviderConfig struct {
	ClientID     string `yaml:"client_id"     env-required:"true"`
	ClientSecret string `yaml:"client_secret" env-required:"true"`
	RedirectURL  string `yaml:"redirect_url"  env-required:"true"`
}

type FederationConfig struct {
	Google   OAuthProviderConfig `yaml:"google" env-prefix:"SSO_FEDERATION_GOOGLE_"`
	GitHub   OAuthProviderConfig `yaml:"github" env-prefix:"SSO_FEDERATION_GITHUB_"`
	StateTTL time.Duration       `yaml:"state_ttl" env:"SSO_FEDERATION_STATE_TTL" env-default:"10m"`
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

type CORSConfig struct {
	AllowOrigins  string `yaml:"allow_origins" env:"SSO_SECURITY_CORS_ALLOW_ORIGINS" env-default:"*"`
	AllowMethods  string `yaml:"allow_methods" env:"SSO_SECURITY_CORS_ALLOW_METHODS" env-default:"GET, POST, PUT, DELETE, OPTIONS"`
	AllowHeaders  string `yaml:"allow_headers" env:"SSO_SECURITY_CORS_ALLOW_HEADERS" env-default:"Content-Type, Authorization, X-Request-ID"`
	ExposeHeaders string `yaml:"expose_headers" env:"SSO_SECURITY_CORS_EXPOSE_HEADERS" env-default:"X-Request-ID"`
	MaxAge        string `yaml:"max_age"        env:"SSO_SECURITY_CORS_MAX_AGE"        env-default:"86400"`
}

type SecurityConfig struct {
	EncryptionKey string          `yaml:"encryption_key" env:"SSO_SECURITY_ENCRYPTION_KEY" env-required:"true"`
	RateLimit     RateLimitConfig `yaml:"rate_limit"`
	CORS          CORSConfig      `yaml:"cors"`
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
