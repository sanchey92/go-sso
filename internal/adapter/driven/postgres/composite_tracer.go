package postgres

import (
	"context"

	"github.com/jackc/pgx/v5"
)

type compositeTracer struct {
	tracers []pgx.QueryTracer
}

func newCompositeTracer(tracers ...pgx.QueryTracer) *compositeTracer {
	return &compositeTracer{tracers: tracers}
}

func (ct *compositeTracer) TraceQueryStart(
	ctx context.Context,
	conn *pgx.Conn,
	data pgx.TraceQueryStartData,
) context.Context {
	for _, t := range ct.tracers {
		ctx = t.TraceQueryStart(ctx, conn, data)
	}
	return ctx
}

func (ct *compositeTracer) TraceQueryEnd(
	ctx context.Context,
	conn *pgx.Conn,
	data pgx.TraceQueryEndData,
) {
	for _, t := range ct.tracers {
		t.TraceQueryEnd(ctx, conn, data)
	}
}
