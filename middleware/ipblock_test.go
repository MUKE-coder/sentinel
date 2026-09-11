package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

type staticBlocks map[string]bool

func (s staticBlocks) IsBlocked(ip string) bool { return s[ip] }

func TestIPBlockMiddleware(t *testing.T) {
	ConfigureTrustedProxies(nil)
	checker := BlockCheckers{staticBlocks{"198.51.100.1": true}, nil, staticBlocks{"198.51.100.2": true}}

	r := gin.New()
	r.Use(IPBlockMiddleware(checker))
	r.GET("/", func(c *gin.Context) { c.Status(http.StatusOK) })

	for ip, want := range map[string]int{
		"198.51.100.1": http.StatusForbidden, // first list
		"198.51.100.2": http.StatusForbidden, // second list
		"198.51.100.3": http.StatusOK,
	} {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = ip + ":4000"
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		if w.Code != want {
			t.Errorf("%s: got %d, want %d", ip, w.Code, want)
		}
	}
}
