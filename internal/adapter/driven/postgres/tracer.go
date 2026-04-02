package postgres

import (
	"context"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/sanchey92/sso/pkg/metrics"
)

type (
	queryStartTimeKey struct{}
	queryStartSQLKey  struct{}
)

type QueryTracer struct {
	metrics *metrics.Metrics
}

func NewQueryTracer(m *metrics.Metrics) *QueryTracer {
	return &QueryTracer{metrics: m}
}

func (t *QueryTracer) TraceQueryStart(
	ctx context.Context,
	_ *pgx.Conn,
	data pgx.TraceQueryStartData,
) context.Context {
	ctx = context.WithValue(ctx, queryStartTimeKey{}, time.Now())
	ctx = context.WithValue(ctx, queryStartSQLKey{}, data.SQL)
	return ctx
}

func (t *QueryTracer) TraceQueryEnd(
	ctx context.Context,
	_ *pgx.Conn,
	_ pgx.TraceQueryEndData,
) {
	startTime, ok := ctx.Value(queryStartTimeKey{}).(time.Time)
	if !ok {
		return
	}

	duration := time.Since(startTime).Seconds()

	sql, _ := ctx.Value(queryStartSQLKey{}).(string)
	operation := classifySQL(sql)
	t.metrics.DBQueryDuration.WithLabelValues(operation).Observe(duration)
}

func classifySQL(sql string) string {
	sql = strings.TrimSpace(sql)
	if sql == "" {
		return "unknown"
	}

	firstSpace := strings.IndexByte(sql, ' ')
	if firstSpace < 0 {
		firstSpace = len(sql)
	}
	op := strings.ToLower(sql[:firstSpace])

	switch op {
	case "select":
		return "select"
	case "insert":
		return "insert"
	case "update":
		return "update"
	case "delete":
		return "delete"
	default:
		return "other"
	}
}
