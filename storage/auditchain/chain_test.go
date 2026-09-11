package auditchain

import (
	"fmt"
	"testing"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

func linked(t *testing.T, c *Chain, n int) []*sentinel.AuditLog {
	t.Helper()
	entries := make([]*sentinel.AuditLog, n)
	for i := range entries {
		e := &sentinel.AuditLog{
			ID:        fmt.Sprintf("e%d", i+1),
			Timestamp: time.Now().Add(time.Duration(i) * time.Second),
			UserID:    "admin",
			Action:    "UPDATE",
			Resource:  "sentinel.waf_config",
			Before:    sentinel.JSONMap{"mode": "block"},
			After:     sentinel.JSONMap{"mode": "log", "rules": map[string]any{"XSS": "strict"}},
			Success:   true,
		}
		c.Link(e)
		entries[i] = e
	}
	return entries
}

func kinds(r Report) []string {
	out := make([]string, len(r.Problems))
	for i, p := range r.Problems {
		out[i] = p.Kind + "@" + fmt.Sprint(p.Seq)
	}
	return out
}

func TestVerify_IntactChain(t *testing.T) {
	entries := linked(t, New(nil), 5)
	// Order in storage doesn't matter.
	entries[0], entries[4] = entries[4], entries[0]
	r := Verify(entries, nil)
	if !r.OK || r.Checked != 5 || r.Chains != 1 {
		t.Fatalf("intact chain should verify: %+v", r)
	}
}

func TestVerify_DetectsModification(t *testing.T) {
	entries := linked(t, New(nil), 5)
	entries[2].UserID = "someone-else"
	r := Verify(entries, nil)
	if r.OK || len(r.Problems) != 1 || r.Problems[0].Kind != ProblemModified || r.Problems[0].Seq != 3 {
		t.Fatalf("expected one modified entry at seq 3, got %v", kinds(r))
	}
}

func TestVerify_DetectsNestedValueEdit(t *testing.T) {
	entries := linked(t, New(nil), 3)
	entries[1].After["rules"] = map[string]any{"XSS": "off"}
	if r := Verify(entries, nil); r.OK {
		t.Fatal("editing a value inside After must be detected")
	}
}

func TestVerify_DetectsDeletion(t *testing.T) {
	entries := linked(t, New(nil), 5)
	withoutMiddle := append([]*sentinel.AuditLog{}, entries[:2]...)
	withoutMiddle = append(withoutMiddle, entries[3:]...)
	r := Verify(withoutMiddle, nil)
	if r.OK || len(r.Problems) != 1 || r.Problems[0].Kind != ProblemMissing || r.Problems[0].Seq != 3 {
		t.Fatalf("expected missing entry 3, got %v", kinds(r))
	}
}

func TestVerify_PrunedHeadIsNotAProblem(t *testing.T) {
	entries := linked(t, New(nil), 5)
	if r := Verify(entries[2:], nil); !r.OK {
		t.Fatalf("losing the oldest entries to retention must not fail verification: %v", kinds(r))
	}
}

func TestVerify_DetectsRewrittenLink(t *testing.T) {
	entries := linked(t, New(nil), 3)
	// Rewrite entry 2 consistently (its own hash recomputed) but without
	// the new hash propagating: entry 3's link breaks.
	entries[1].UserID = "forged"
	entries[1].Hash = Hash(entries[1], nil)
	r := Verify(entries, nil)
	if r.OK || len(r.Problems) != 1 || r.Problems[0].Kind != ProblemBrokenLink || r.Problems[0].Seq != 3 {
		t.Fatalf("expected broken link at seq 3, got %v", kinds(r))
	}
}

func TestVerify_KeyedChainRejectsWrongKey(t *testing.T) {
	entries := linked(t, New([]byte("k1")), 3)
	if r := Verify(entries, []byte("k1")); !r.OK || !r.Keyed {
		t.Fatalf("keyed chain should verify with its key: %+v", r)
	}
	if r := Verify(entries, []byte("k2")); r.OK {
		t.Fatal("verifying with the wrong key must fail")
	}
	if r := Verify(entries, nil); r.OK {
		t.Fatal("a keyed chain must not verify as plain SHA-256")
	}
}

func TestVerify_CountsUnchainedAndSeparatesChains(t *testing.T) {
	a := linked(t, New(nil), 2)
	b := linked(t, New(nil), 3)
	legacy := &sentinel.AuditLog{ID: "old", Action: "CREATE"}
	all := append(append(a, b...), legacy)
	r := Verify(all, nil)
	if !r.OK || r.Chains != 2 || r.Checked != 5 || r.Unchained != 1 {
		t.Fatalf("expected 2 chains, 5 checked, 1 unchained: %+v", r)
	}
}
