package safefetch

import (
	"context"
	"errors"
	"fmt"
	"net"
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

func TestClient_BlocksUnspecifiedIPv6(t *testing.T) {
	client := Client(Options{})
	_, err := client.Get("http://[::]:6379/")
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected [::] (dials localhost) to be blocked, got %v", err)
	}
}

// TestClient_AllowsExplicitHost exercises AllowedHosts end to end, without
// AllowPrivateRanges. Before v2.2.2 the connect-time guard never consulted
// AllowedHosts, so an allowed host that resolved to a private address passed
// validation and then failed at dial — this test used to need
// AllowPrivateRanges to pass, which hid the bug.
func TestClient_AllowsExplicitHost(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	host := strings.TrimPrefix(srv.URL, "http://")
	host = strings.Split(host, ":")[0]
	client := Client(Options{AllowedHosts: []string{host}})
	resp, err := client.Get(srv.URL)
	if err != nil {
		t.Fatalf("explicit allowed host should succeed, got %v", err)
	}
	resp.Body.Close()
}

func TestClient_BlocksRedirectToInternal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://169.254.169.254/latest/meta-data/", http.StatusFound)
	}))
	defer srv.Close()

	rep := &stubReporter{}
	client := Client(Options{AllowedHosts: []string{"127.0.0.1"}, Reporter: rep})
	_, err := client.Get(srv.URL)
	if !errors.Is(err, ErrBlocked) {
		t.Fatalf("expected redirect to metadata IP to be blocked, got %v", err)
	}
	if rep.calls == 0 {
		t.Fatal("expected the blocked redirect to be reported")
	}
}

func TestClient_ReportsBlockedToSentinel(t *testing.T) {
	rep := &stubReporter{}
	client := Client(Options{Reporter: rep})
	_, _ = client.Get("http://169.254.169.254/")
	if rep.calls == 0 {
		t.Fatal("expected SSRF block to be reported to Sentinel pipeline")
	}
}

// stubResolver stands in for the pre-flight resolver. Unknown hosts fail
// the lookup, like NXDOMAIN.
func stubResolver(t *testing.T, answers map[string][]string) {
	t.Helper()
	prev := lookupIPAddr
	lookupIPAddr = func(_ context.Context, host string) ([]net.IPAddr, error) {
		ips, ok := answers[host]
		if !ok {
			return nil, fmt.Errorf("no such host %q", host)
		}
		out := make([]net.IPAddr, 0, len(ips))
		for _, s := range ips {
			out = append(out, net.IPAddr{IP: net.ParseIP(s)})
		}
		return out, nil
	}
	t.Cleanup(func() { lookupIPAddr = prev })
}

func validate(t *testing.T, rawURL string) error {
	t.Helper()
	req, err := http.NewRequest("GET", rawURL, nil)
	if err != nil {
		t.Fatalf("NewRequest(%q): %v", rawURL, err)
	}
	return validateRequest(req, Options{AllowedSchemes: []string{"http", "https"}}, nil, nil)
}

// TestValidateRequest_BlocksBypassEncodings is the table of SSRF encoding
// tricks. The resolver stub answers the way getaddrinfo does for numeric
// host forms, so these prove the resolved address is what gets checked.
func TestValidateRequest_BlocksBypassEncodings(t *testing.T) {
	stubResolver(t, map[string][]string{
		"2130706433":   {"127.0.0.1"},                  // decimal
		"0x7f.1":       {"127.0.0.1"},                  // hex + short form
		"017700000001": {"127.0.0.1"},                  // octal
		"rebind.test":  {"93.184.216.34", "127.0.0.1"}, // one internal answer among public ones
		"localtest.me": {"127.0.0.1"},                  // public DNS name pointing at loopback
		"nat64.test":   {"64:ff9b::a9fe:a9fe"},
	})

	for _, rawURL := range []string{
		"http://[::]/",
		"http://[::ffff:127.0.0.1]/",
		"http://[::ffff:a9fe:a9fe]/",    // mapped 169.254.169.254, hex form
		"http://[64:ff9b::a9fe:a9fe]/",  // NAT64-embedded 169.254.169.254
		"http://[2002:7f00:1::]/",       // 6to4-embedded 127.0.0.1
		"http://[2001:0:4136:e378::1]/", // Teredo
		"http://[fe80::1%25eth0]/",      // zoned link-local
		"http://[fd00:ec2::254]/",       // AWS IPv6 metadata
		"http://0.0.0.0/",
		"http://192.0.0.192/",     // Oracle Cloud metadata
		"http://100.100.100.200/", // Alibaba Cloud metadata
		"http://255.255.255.255/",
		"http://metadata.google.internal./", // trailing root dot
		"http://METADATA.GOOG/",
		"http://2130706433/",
		"http://0x7f.1/",
		"http://017700000001/",
		"http://rebind.test/",
		"http://localtest.me/",
		"http://nat64.test/",
	} {
		if err := validate(t, rawURL); !errors.Is(err, ErrBlocked) {
			t.Errorf("%s: expected ErrBlocked, got %v", rawURL, err)
		}
	}
}

func TestValidateRequest_AllowsPublicTargets(t *testing.T) {
	stubResolver(t, map[string][]string{
		"public.test": {"93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"},
	})

	for _, rawURL := range []string{
		"http://public.test/",
		"https://93.184.216.34/",
		"http://[64:ff9b::5db8:d822]/", // NAT64 to 93.184.216.34 — DNS64 on IPv6-only hosts
		"http://[2002:5db8:d822::1]/",  // 6to4 to 93.184.216.34
	} {
		if err := validate(t, rawURL); err != nil {
			t.Errorf("%s: expected allowed, got %v", rawURL, err)
		}
	}
}

// TestDialControl_BlocksResolvedInternalIP covers DNS rebinding: whatever
// the pre-flight lookup saw, the connect-time guard judges the address
// actually being dialled.
func TestDialControl_BlocksResolvedInternalIP(t *testing.T) {
	ctrl := dialControl(Options{}, nil)
	for _, addr := range []string{"127.0.0.1:80", "[::]:80", "[::ffff:169.254.169.254]:80", "[64:ff9b::a00:5]:80"} {
		if err := ctrl("tcp", addr, nil); !errors.Is(err, ErrBlocked) {
			t.Errorf("dial to %s: expected ErrBlocked, got %v", addr, err)
		}
	}
	if err := ctrl("tcp4", "93.184.216.34:443", nil); err != nil {
		t.Errorf("dial to public address: expected allowed, got %v", err)
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
