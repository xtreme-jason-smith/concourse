package auth

import (
	"context"
	"net/http"

	"github.com/concourse/concourse/skymarshal/token"
)

//go:generate counterfeiter net/http.Handler

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

type WebAuthHandler struct {
	Handler    http.Handler
	Middleware token.Middleware
}

func (handler WebAuthHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tokenString := handler.Middleware.GetAuthToken(r)
	if tokenString != "" {
		ctx := context.WithValue(r.Context(), CSRFRequiredKey, handler.isCSRFRequired(r))
		r = r.WithContext(ctx)

		if r.Header.Get("Authorization") == "" {
			r.Header.Set("Authorization", tokenString)
		}
	}

	recorder := &responseRecorder{ResponseWriter: w}
	handler.Handler.ServeHTTP(recorder, r)

	if tokenString != "" && recorder.statusCode == http.StatusUnauthorized {
		handler.Middleware.UnsetAuthToken(w)
	}
}

// We don't validate CSRF token for GET requests
// since they are not changing the state
func (handler WebAuthHandler) isCSRFRequired(r *http.Request) bool {
	return (r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions)
}

func IsCSRFRequired(r *http.Request) bool {
	required, ok := r.Context().Value(CSRFRequiredKey).(bool)
	return ok && required
}
