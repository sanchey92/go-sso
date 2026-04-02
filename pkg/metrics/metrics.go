package metrics

import "github.com/prometheus/client_golang/prometheus"

type Metrics struct {
	HTTPRequestsTotal   *prometheus.CounterVec
	HTTPRequestDuration *prometheus.HistogramVec

	AuthLoginTotal           *prometheus.CounterVec
	AuthTokenIssuedTotal     *prometheus.CounterVec
	AuthMFAVerificationTotal *prometheus.CounterVec

	GRPCRequestsTotal   *prometheus.CounterVec
	GRPCRequestDuration *prometheus.HistogramVec

	DBQueryDuration *prometheus.HistogramVec

	RedisOperationDuration *prometheus.HistogramVec
}

func New() *Metrics {
	m := &Metrics{
		// HTTP
		HTTPRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sso",
				Subsystem: "http",
				Name:      "requests_total",
				Help:      "Total number of HTTP requests.",
			},
			[]string{"method", "path", "status"},
		),
		HTTPRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "sso",
				Subsystem: "http",
				Name:      "request_duration_seconds",
				Help:      "Duration of HTTP requests in seconds.",
				Buckets:   []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10},
			},
			[]string{"method", "path"},
		),

		// Business
		AuthLoginTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sso",
				Subsystem: "auth",
				Name:      "login_total",
				Help:      "Total login attempts by method and status.",
			},
			[]string{"method", "status"},
			// method: password, federation, magic_link
			// status: success, failure, mfa_required
		),
		AuthTokenIssuedTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sso",
				Subsystem: "auth",
				Name:      "token_issued_total",
				Help:      "Total tokens issued by type.",
			},
			[]string{"type"}, // access, refresh
		),
		AuthMFAVerificationTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sso",
				Subsystem: "auth",
				Name:      "mfa_verification_total",
				Help:      "Total MFA verification attempts.",
			},
			[]string{"status"}, // success, failure
		),

		// gRPC
		GRPCRequestsTotal: prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: "sso",
				Subsystem: "grpc",
				Name:      "requests_total",
				Help:      "Total number of gRPC requests.",
			},
			[]string{"method", "status"},
		),
		GRPCRequestDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "sso",
				Subsystem: "grpc",
				Name:      "request_duration_seconds",
				Help:      "Duration of gRPC requests in seconds.",
				Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5},
			},
			[]string{"method"},
		),

		// Database
		DBQueryDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "sso",
				Subsystem: "db",
				Name:      "query_duration_seconds",
				Help:      "Duration of database queries in seconds.",
				Buckets:   []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 5},
			},
			[]string{"operation"}, // select, insert, update, delete
		),

		// Redis
		RedisOperationDuration: prometheus.NewHistogramVec(
			prometheus.HistogramOpts{
				Namespace: "sso",
				Subsystem: "redis",
				Name:      "operation_duration_seconds",
				Help:      "Duration of Redis operations in seconds.",
				Buckets:   []float64{0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5},
			},
			[]string{"operation"}, // set, get, delete, allow (rate limiter)
		),
	}
	prometheus.MustRegister(
		m.HTTPRequestsTotal,
		m.HTTPRequestDuration,
		m.AuthLoginTotal,
		m.AuthTokenIssuedTotal,
		m.AuthMFAVerificationTotal,
		m.GRPCRequestsTotal,
		m.GRPCRequestDuration,
		m.DBQueryDuration,
		m.RedisOperationDuration,
	)

	return m
}

// NewTest creates unregistered Metrics for use in unit tests.
func NewTest() *Metrics {
	return &Metrics{
		HTTPRequestsTotal:        prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_http_total"}, []string{"method", "path", "status"}),
		HTTPRequestDuration:      prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "test_http_dur"}, []string{"method", "path"}),
		AuthLoginTotal:           prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_auth_login"}, []string{"method", "status"}),
		AuthTokenIssuedTotal:     prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_auth_token"}, []string{"type"}),
		AuthMFAVerificationTotal: prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_auth_mfa"}, []string{"status"}),
		GRPCRequestsTotal:        prometheus.NewCounterVec(prometheus.CounterOpts{Name: "test_grpc_total"}, []string{"method", "status"}),
		GRPCRequestDuration:      prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "test_grpc_dur"}, []string{"method"}),
		DBQueryDuration:          prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "test_db_dur"}, []string{"operation"}),
		RedisOperationDuration:   prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: "test_redis_dur"}, []string{"operation"}),
	}
}
