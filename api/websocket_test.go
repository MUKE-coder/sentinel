package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// The WebSocket endpoints stream the live threat feed (attacker IPs, matched
// payloads, request paths). A missing or invalid token must be rejected —
// before v2.1.0 the token was only validated when present, so any
// unauthenticated client could subscribe.
func TestWebSocketEndpointsRequireToken(t *testing.T) {
	r, _, _ := newCSPTestServer(t)

	endpoints := []string{
		"/sentinel/ws/threats",
		"/sentinel/ws/metrics",
		"/sentinel/ws/alerts",
	}

	for _, ep := range endpoints {
		t.Run(ep+" no token", func(t *testing.T) {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, ep, nil))
			if w.Code != http.StatusUnauthorized {
				t.Errorf("expected 401 without token, got %d", w.Code)
			}
		})
		t.Run(ep+" bad token", func(t *testing.T) {
			w := httptest.NewRecorder()
			r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, ep+"?token=not-a-jwt", nil))
			if w.Code != http.StatusUnauthorized {
				t.Errorf("expected 401 with invalid token, got %d", w.Code)
			}
		})
	}
}

// A valid token must pass the auth gate. The upgrade itself then fails on a
// plain HTTP request (no Upgrade header), which is fine — we only assert the
// request got past authorization.
func TestWebSocketAcceptsValidToken(t *testing.T) {
	r, _, _ := newCSPTestServer(t)

	token, err := GenerateToken("test")
	if err != nil {
		t.Fatalf("GenerateToken: %v", err)
	}

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/sentinel/ws/threats?token="+token, nil))
	if w.Code == http.StatusUnauthorized {
		t.Errorf("valid token rejected with 401: %s", w.Body.String())
	}
}
