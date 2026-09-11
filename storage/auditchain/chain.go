// Package auditchain links audit log entries into hash chains so that editing
// or deleting an entry after it was written can be detected.
//
// Each process writes its own chain: every entry records the chain's ID, its
// position in it, the previous entry's hash, and a hash over its own
// canonical form (which includes that link). Verify recomputes the hashes and
// walks each chain, reporting modified entries, gaps where entries were
// deleted, and broken links.
//
// Without a key the hash is plain SHA-256, which catches accidental damage and
// naive edits but not someone who rewrites the whole chain. With a key it is
// an HMAC-SHA256: rewriting the chain undetectably then requires the key, so
// keep it outside the database.
package auditchain

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"sort"
	"sync"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
	"github.com/google/uuid"
)

// Chain assigns each audit entry its place in this process's chain.
type Chain struct {
	mu   sync.Mutex
	id   string
	seq  int64
	prev string
	key  []byte
}

// New starts a chain. A non-empty key makes every hash an HMAC-SHA256.
func New(key []byte) *Chain {
	return &Chain{id: uuid.NewString(), key: key}
}

// ID returns the chain's identifier.
func (c *Chain) ID() string { return c.id }

// Link gives entry the next position in the chain and sets its hashes. Call
// it exactly once per entry, before the entry is stored; entries may be
// stored in any order afterwards.
func (c *Chain) Link(entry *sentinel.AuditLog) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.seq++
	// Postgres keeps microseconds; truncating first means the hash survives
	// a storage round trip on every backend.
	entry.Timestamp = entry.Timestamp.UTC().Truncate(time.Microsecond)
	entry.ChainID = c.id
	entry.ChainSeq = c.seq
	entry.PrevHash = c.prev
	entry.Hash = Hash(entry, c.key)
	c.prev = entry.Hash
}

// Hash computes an entry's hash over its canonical form. The Hash field
// itself is not part of the input.
func Hash(entry *sentinel.AuditLog, key []byte) string {
	var h hash.Hash
	if len(key) > 0 {
		h = hmac.New(sha256.New, key)
	} else {
		h = sha256.New()
	}
	h.Write(canonical(entry))
	return hex.EncodeToString(h.Sum(nil))
}

// canonical is the byte form an entry is hashed over: fixed field order,
// timestamp as UTC microseconds, and Before/After as JSON (encoding/json
// sorts map keys), so the same entry hashes the same after any store's
// round trip.
func canonical(e *sentinel.AuditLog) []byte {
	before := mapJSON(e.Before)
	after := mapJSON(e.After)
	v := struct {
		ChainID    string          `json:"chain_id"`
		ChainSeq   int64           `json:"chain_seq"`
		PrevHash   string          `json:"prev_hash"`
		ID         string          `json:"id"`
		Timestamp  int64           `json:"timestamp_us"`
		UserID     string          `json:"user_id"`
		UserEmail  string          `json:"user_email"`
		UserRole   string          `json:"user_role"`
		Action     string          `json:"action"`
		Resource   string          `json:"resource"`
		ResourceID string          `json:"resource_id"`
		Before     json.RawMessage `json:"before"`
		After      json.RawMessage `json:"after"`
		IP         string          `json:"ip"`
		UserAgent  string          `json:"user_agent"`
		Success    bool            `json:"success"`
		Error      string          `json:"error"`
		RequestID  string          `json:"request_id"`
	}{
		ChainID:    e.ChainID,
		ChainSeq:   e.ChainSeq,
		PrevHash:   e.PrevHash,
		ID:         e.ID,
		Timestamp:  e.Timestamp.UnixMicro(),
		UserID:     e.UserID,
		UserEmail:  e.UserEmail,
		UserRole:   e.UserRole,
		Action:     e.Action,
		Resource:   e.Resource,
		ResourceID: e.ResourceID,
		Before:     before,
		After:      after,
		IP:         e.IP,
		UserAgent:  e.UserAgent,
		Success:    e.Success,
		Error:      e.Error,
		RequestID:  e.RequestID,
	}
	out, _ := json.Marshal(v)
	return out
}

// mapJSON renders a Before/After map for hashing. Nil and empty maps render
// the same, because a store round trip can turn one into the other.
func mapJSON(m sentinel.JSONMap) json.RawMessage {
	if len(m) == 0 {
		return json.RawMessage("null")
	}
	out, err := json.Marshal(map[string]any(m))
	if err != nil {
		return json.RawMessage("null")
	}
	return out
}

// Problem kinds reported by Verify.
const (
	ProblemModified   = "modified"    // the entry's content no longer matches its hash
	ProblemMissing    = "missing"     // entries between two chained entries were deleted
	ProblemBrokenLink = "broken_link" // an entry's prev_hash doesn't match its predecessor
)

// Problem is one integrity failure found by Verify.
type Problem struct {
	Kind    string `json:"kind"`
	ChainID string `json:"chain_id"`
	Seq     int64  `json:"seq"`
	EntryID string `json:"entry_id,omitempty"`
	Detail  string `json:"detail"`
}

// Report summarizes a verification run.
type Report struct {
	OK        bool      `json:"ok"`
	Checked   int       `json:"checked"`   // chained entries verified
	Unchained int       `json:"unchained"` // entries written without a chain (before v2.4.0, or saved directly to the store)
	Chains    int       `json:"chains"`
	Keyed     bool      `json:"keyed"`
	Problems  []Problem `json:"problems"`
}

// Verify checks entries, given in any order. The oldest entry of each chain
// may have lost its predecessor to retention pruning; that is not reported.
// Deleting the newest entries of a chain whose process has since stopped
// cannot be detected — nothing references them.
func Verify(entries []*sentinel.AuditLog, key []byte) Report {
	report := Report{Keyed: len(key) > 0, Problems: []Problem{}}
	chains := make(map[string][]*sentinel.AuditLog)
	for _, e := range entries {
		if e.ChainID == "" {
			report.Unchained++
			continue
		}
		chains[e.ChainID] = append(chains[e.ChainID], e)
	}
	report.Chains = len(chains)

	ids := make([]string, 0, len(chains))
	for id := range chains {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		chain := chains[id]
		sort.Slice(chain, func(i, j int) bool { return chain[i].ChainSeq < chain[j].ChainSeq })
		for i, e := range chain {
			report.Checked++
			if Hash(e, key) != e.Hash {
				report.Problems = append(report.Problems, Problem{
					Kind: ProblemModified, ChainID: id, Seq: e.ChainSeq, EntryID: e.ID,
					Detail: "content does not match the entry's hash",
				})
			}
			if i == 0 {
				continue
			}
			prev := chain[i-1]
			switch {
			case e.ChainSeq == prev.ChainSeq:
				report.Problems = append(report.Problems, Problem{
					Kind: ProblemBrokenLink, ChainID: id, Seq: e.ChainSeq, EntryID: e.ID,
					Detail: "two entries claim the same position",
				})
			case e.ChainSeq != prev.ChainSeq+1:
				report.Problems = append(report.Problems, Problem{
					Kind: ProblemMissing, ChainID: id, Seq: prev.ChainSeq + 1,
					Detail: fmt.Sprintf("entries %d–%d are missing", prev.ChainSeq+1, e.ChainSeq-1),
				})
			case e.PrevHash != prev.Hash:
				report.Problems = append(report.Problems, Problem{
					Kind: ProblemBrokenLink, ChainID: id, Seq: e.ChainSeq, EntryID: e.ID,
					Detail: "prev_hash does not match the preceding entry",
				})
			}
		}
	}
	report.OK = len(report.Problems) == 0
	return report
}
