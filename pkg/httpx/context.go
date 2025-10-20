package httpx

import "context"

type ctxKey string

const (
	CtxKeyUserID ctxKey = "user_id"
	CtxKeyScopes ctxKey = "scopes"
	CtxKeyClaims ctxKey = "claims" // if you want full jwtx.Claims
)

func scopesFromCtx(ctx context.Context) []string {
	if v, ok := ctx.Value(CtxKeyScopes).([]string); ok {
		return v
	}
	return nil
}
