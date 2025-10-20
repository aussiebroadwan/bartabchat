package slogx

import (
	"context"
	"log/slog"
)

type ctxKey struct{}

func WithContext(ctx context.Context, logger *slog.Logger) context.Context {
	return context.WithValue(ctx, ctxKey{}, logger)
}

func FromContext(ctx context.Context) *slog.Logger {
	l, ok := ctx.Value(ctxKey{}).(*slog.Logger)
	if !ok {
		return slog.Default()
	}
	return l
}

func WithRequestID(ctx context.Context, reqID string) context.Context {
	l := FromContext(ctx)
	return WithContext(ctx, l.With("req_id", reqID))
}
