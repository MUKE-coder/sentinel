package intelligence

import (
	"context"
	"testing"
	"time"

	"github.com/MUKE-coder/sentinel/v2/storage/memory"
)

// A block or whitelist entry written anywhere else — another replica, or the
// database directly — reaches this process on the next sync. Before v2.5.1
// the whitelist was never read back at all: entries were lost on restart and
// never shared between replicas.
func TestIPManagerSyncsFromStorage(t *testing.T) {
	ctx := context.Background()
	store := memory.New()

	mgr := NewIPManagerWithSync(store, 0) // no background goroutine; sync by hand
	defer mgr.Stop()

	if err := store.BlockIP(ctx, "203.0.113.7", "blocked on another replica", nil); err != nil {
		t.Fatal(err)
	}
	if err := store.WhitelistIP(ctx, "198.51.100.4"); err != nil {
		t.Fatal(err)
	}

	if mgr.IsBlocked("203.0.113.7") {
		t.Error("the cache should not know about the block before it syncs")
	}

	mgr.sync()
	if !mgr.IsBlocked("203.0.113.7") {
		t.Error("a block made on another replica must apply after a sync")
	}
	if !mgr.IsWhitelisted("198.51.100.4") {
		t.Error("a whitelist entry made on another replica must apply after a sync")
	}

	// A fresh manager stands for a restart: it must start from storage.
	restarted := NewIPManagerWithSync(store, 0)
	defer restarted.Stop()
	if !restarted.IsBlocked("203.0.113.7") {
		t.Error("a restart must load blocked IPs from storage")
	}
	if !restarted.IsWhitelisted("198.51.100.4") {
		t.Error("a restart must load the whitelist from storage")
	}

	if err := store.UnblockIP(ctx, "203.0.113.7"); err != nil {
		t.Fatal(err)
	}
	mgr.sync()
	if mgr.IsBlocked("203.0.113.7") {
		t.Error("an unblock made on another replica must apply after a sync")
	}
}

// The background goroutine applies changes without anyone calling sync.
func TestIPManagerBackgroundSyncPicksUpChanges(t *testing.T) {
	store := memory.New()
	mgr := NewIPManagerWithSync(store, 10*time.Millisecond)
	defer mgr.Stop()

	if err := store.BlockIP(context.Background(), "203.0.113.9", "elsewhere", nil); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for !mgr.IsBlocked("203.0.113.9") {
		if time.Now().After(deadline) {
			t.Fatal("the background sync did not apply a block within 2s")
		}
		time.Sleep(5 * time.Millisecond)
	}
}
