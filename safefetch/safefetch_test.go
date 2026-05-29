package safefetch

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClient_BlocksAWSIMDS(t *testing.T) {
	client := Client(Options{})
	_, err := client.Get("http://169.254.169.254/latest/meta-data/")
	if !errors.Is(err, ErrBlocked) && !strings.Contains(safeErrString(err), "blocked") {
		t.Fatalf("expected SSRF block for AWS IMDS, got %v", err)
	}
}

func TestClient_BlocksLoopback(t *testing.T) {
	client := Client(Options{})
	_, err := client.Get("http://127.0.0.1:8080/")
	if !errors.Is(err, ErrBlocked) && !strings.Contains(safeErrString(err), "blocked") {
		t.Fatalf("expected block for loopback, got %v", err)
	}
}

func TestClient_BlocksRFC1918(t *testing.T) {
	client := Client(Options{})
	_, err := client.Get("http://10.0.0.5/")
	if !errors.Is(err, ErrBlocked) && !strings.Contains(safeErrString(err), "blocked") {
		t.Fatalf("expected block for 10/8, got %v", err)
	}
}

func TestClient_BlocksMetadataHostname(t *testing.T) {
	client := Client(Options{})
	_, err := client.Get("http://metadata.google.internal/computeMetadata/v1/")
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected metadata.google.internal to be blocked, got %v", err)
	}
}

func TestClient_BlocksFileScheme(t *testing.T) {
	client := Client(Options{})
	_, err := client.Get("file:///etc/passwd")
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected scheme block, got %v", err)
	}
}

func TestClient_AllowsExplicitHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// httptest binds to 127.0.0.1 — loopback. Without AllowedHosts this would
	// be blocked. We exercise the explicit-allowlist path.
	host := strings.TrimPrefix(srv.URL, "http://")
	host = strings.Split(host, ":")[0]
	client := Client(Options{
		AllowedHosts:       []string{host},
		AllowPrivateRanges: true, // Dialer.Control re-checks; allow loopback for the test
	})
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("explicit allowed host should succeed, got %v", err)
	}
	resp.Body.Close()
}

func TestClient_ReportsBlockedToSentinel(t *testing.T) {
	rep := &stubReporter{}
	client := Client(Options{Reporter: rep})
	_, _ = client.Get("http://169.254.169.254/")
	if rep.calls == 0 {
		t.Fatal("expected SSRF block to be reported to Sentinel pipeline")
	}
}

type stubReporter struct{ calls int }

func (s *stubReporter) EmitThreat(_ interface{}) { s.calls++ }

func safeErrString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
