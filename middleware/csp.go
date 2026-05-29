package middleware

import (
	"strings"

	sentinel "github.com/MUKE-coder/sentinel/core"
	"github.com/gin-gonic/gin"
)

// CSPMode controls whether the policy is enforced or only reported on.
type CSPMode string

const (
	// CSPReportOnly emits Content-Security-Policy-Report-Only. Browsers send
	// violation reports but do not block. Recommended for initial rollout.
	CSPReportOnly CSPMode = "report-only"

	// CSPEnforce emits Content-Security-Policy. Browsers block violating
	// resources AND send reports.
	CSPEnforce CSPMode = "enforce"
)

// CSPConfig configures the CSP header middleware.
type CSPConfig struct {
	// Enabled turns the middleware on. Default false (additive feature).
	Enabled bool

	// Mode is "report-only" or "enforce". Empty defaults to report-only —
	// the safer choice for a freshly-enabled policy.
	Mode CSPMode

	// Directives is the rendered policy body, e.g.
	// "default-src 'self'; script-src 'self' 'nonce-XYZ'". If empty, a
	// conservative default is used.
	Directives string

	// ReportURI is appended to the directives as `report-uri <ReportURI>`.
	// Set this to the path the dashboard mounts the CSP receiver at —
	// commonly "/sentinel/csp-report".
	ReportURI string
}

// CSPMiddleware injects a Content-Security-Policy (or -Report-Only) header
// on every response. Pair with the CSP-report receiver mounted by the API
// server to actually see what's being blocked.
func CSPMiddleware(cfg CSPConfig) gin.HandlerFunc {
	if !cfg.Enabled {
		return func(c *gin.Context) { c.Next() }
	}

	directives := cfg.Directives
	if directives == "" {
		directives = "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'"
	}
	if cfg.ReportURI != "" {
		directives = strings.TrimRight(directives, "; ") + "; report-uri " + cfg.ReportURI
	}

	headerName := "Content-Security-Policy-Report-Only"
	if cfg.Mode == CSPEnforce {
		headerName = "Content-Security-Policy"
	}

	return func(c *gin.Context) {
		c.Header(headerName, directives)
		c.Next()
	}
}

// DefaultCSPSeverity returns the Severity assigned to CSP violation reports.
// Exposed so tests / handlers stay in sync with the policy choice (Low —
// most violations are extensions or inline scripts; chain in user logic to
// escalate).
func DefaultCSPSeverity() sentinel.Severity {
	return sentinel.SeverityLow
}
