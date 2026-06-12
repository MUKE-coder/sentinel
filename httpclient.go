package sentinel

import (
	"net/http"

	"github.com/MUKE-coder/sentinel/v2/safefetch"
)

// HTTPClientOptions re-exports safefetch.Options at the package root so
// callers get the SSRF-hardened client without a second import path.
type HTTPClientOptions = safefetch.Options

// HTTPClient returns an SSRF-hardened *http.Client. Defaults reject
// loopback, link-local, CGNAT, RFC1918 private, cloud metadata IPs
// (169.254.169.254 etc) and cloud metadata hostnames at request build,
// redirect, and TCP connect time — closing the DNS-rebinding TOCTOU
// window. Use for any outbound HTTP triggered by user input: webhook
// delivery, "fetch from URL" features, OEmbed, link preview, etc.
//
// Pass HTTPClientOptions{Reporter: pipe} where pipe is the Sentinel
// event pipeline to surface every blocked attempt as an SSRF ThreatEvent
// in the dashboard.
func HTTPClient(opts ...HTTPClientOptions) *http.Client {
	var o HTTPClientOptions
	if len(opts) > 0 {
		o = opts[0]
	}
	return safefetch.Client(o)
}
