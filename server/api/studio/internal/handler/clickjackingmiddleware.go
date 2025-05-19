package handler

import (
	"net/http"
)

type ClickjackingMiddleware struct{}

func NewClickjackingMiddleware() *ClickjackingMiddleware {
	return &ClickjackingMiddleware{}
}

func (m *ClickjackingMiddleware) Handle(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		next(w, r)
	}
}