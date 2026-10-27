package detection

import (
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

// Mass scanners walk a list of env-file names looking for API keys. These
// are the shapes seen in one deployment's threat log in a single day, and
// the prefixed ones ("/sendgrid.env", "/gemini.env") stopped being detected
// in v2.4.0, when the pattern was tightened to clear a "report.env.pdf"
// false positive.
func TestEnvProbesAreDetected(t *testing.T) {
	probes := []string{
		"/.env",
		"/.env.local",
		"/.env.prod",
		"/.env.production",
		"/.env.dev",
		"/.env.development",
		"/.env.bak",
		"/dev/.env",
		"/store/.env",
		"/server/.env",
		"/web/.env",
		"/laravel/.env",
		"/gemini.env",
		"/sendgrid.env",
		"/laravel.env",
		"/api/.env.backup",
	}
	for _, path := range probes {
		t.Run(path, func(t *testing.T) {
			if !flaggedAs(ClassifyRequest(sentinel.InspectedRequest{Method: "GET", Path: path}), sentinel.ThreatLFI) {
				t.Errorf("%s was not detected as LFI", path)
			}
		})
	}

	// A query parameter pointing at one counts too.
	if !flaggedAs(ClassifyRequest(sentinel.InspectedRequest{RawQuery: "file=.env.production"}), sentinel.ThreatLFI) {
		t.Error("an env file named in a query parameter was not detected")
	}
}

// Documents and pages that merely contain "env" are not probes. The first
// of these is the false positive the v2.4.0 tightening was for; it has to
// stay clean.
func TestEnvLookalikesArePassed(t *testing.T) {
	clean := []sentinel.InspectedRequest{
		{Method: "GET", Path: "/files/report.env.pdf"},
		{Method: "GET", Path: "/exports/q3.env.csv"},
		{Method: "GET", Path: "/environment/settings"},
		{Method: "GET", Path: "/blog/how-we-use-dotenv-in-ci"},
		{Method: "GET", Path: "/guides/web.config-explained"},
		{RawQuery: "q=how to use .env files in docker"},
		{RawQuery: "q=dotenv vs environment variables"},
	}
	for _, req := range clean {
		where := req.Path
		if where == "" {
			where = req.RawQuery
		}
		t.Run(where, func(t *testing.T) {
			if flaggedAs(ClassifyRequest(req), sentinel.ThreatLFI) {
				t.Errorf("%s was flagged as LFI", where)
			}
		})
	}
}

func flaggedAs(matches []ThreatMatch, want sentinel.ThreatType) bool {
	for _, m := range matches {
		if m.ThreatType == want {
			return true
		}
	}
	return false
}
