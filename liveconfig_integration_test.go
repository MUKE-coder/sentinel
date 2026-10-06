package sentinel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// Two replicas of one application sharing one database. A WAF mode change
// made through one replica's dashboard has to reach the other and survive a
// restart: before v2.6.0 it applied to the process that served the request
// and was lost when that process exited.
func TestMountE_DashboardSettingsReachReplicasAndRestarts(t *testing.T) {
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	defer gin.SetMode(prev)

	// One shared in-memory database stands for the database the replicas of
	// a deployment share. A file would do as well, but Windows can't delete
	// one that is still open, and nothing closes a mounted store.
	dsn := "file:liveconfig_replicas?mode=memory&cache=shared&_pragma=busy_timeout(5000)"

	newReplica := func() *gin.Engine {
		t.Helper()
		r := gin.New()
		cfg := Config{
			Storage:   StorageConfig{Driver: SQLite, DSN: dsn, SyncInterval: 20 * time.Millisecond},
			Dashboard: DashboardConfig{Password: "correct-horse-battery", SecretKey: "settings-secret"},
			WAF:       WAFConfig{Enabled: true, Mode: ModeLog},
		}
		if err := MountE(r, nil, cfg); err != nil {
			t.Fatalf("MountE: %v", err)
		}
		r.GET("/api/items", func(c *gin.Context) { c.Status(http.StatusOK) })
		return r
	}

	do := func(r *gin.Engine, method, path, token, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = "192.0.2.10:5000"
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	// A SQL injection attempt: logged in ModeLog, refused in ModeBlock.
	const attack = "/api/items?id=1%27%20OR%20%271%27%3D%271"
	attackCode := func(r *gin.Engine) int { return do(r, "GET", attack, "", "").Code }

	waitFor := func(r *gin.Engine, want int, what string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for attackCode(r) != want {
			if time.Now().After(deadline) {
				t.Fatalf("%s: still %d after 5s, want %d", what, attackCode(r), want)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}

	replicaA, replicaB := newReplica(), newReplica()

	if code := attackCode(replicaA); code != http.StatusOK {
		t.Fatalf("configured mode is log, so the attack should pass: got %d", code)
	}
	if code := attackCode(replicaB); code != http.StatusOK {
		t.Fatalf("replica B should start in log mode too: got %d", code)
	}

	w := do(replicaA, "POST", "/sentinel/api/auth/login", "", `{"username":"admin","password":"correct-horse-battery"}`)
	var login struct {
		Token string `json:"token"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &login) != nil {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}

	// The dashboard switches the WAF to block on replica A.
	w = do(replicaA, "PUT", "/sentinel/api/waf/rules", login.Token, `{"mode":"block"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("PUT waf/rules: %d %s", w.Code, w.Body.String())
	}
	var updated struct {
		Warning string `json:"warning"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &updated); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if updated.Warning != "" {
		t.Fatalf("the change was not stored: %s", updated.Warning)
	}

	if code := attackCode(replicaA); code != http.StatusForbidden {
		t.Errorf("the replica that made the change must block at once: got %d", code)
	}
	waitFor(replicaB, http.StatusForbidden, "replica B did not pick up the mode change")

	// A fresh replica stands for a restart or a new instance scaling up.
	waitFor(newReplica(), http.StatusForbidden, "a new replica did not start from the stored settings")

	// Discarding the stored settings puts the configured mode back
	// everywhere.
	if w := do(replicaA, "DELETE", "/sentinel/api/settings/live", login.Token, ""); w.Code != http.StatusOK {
		t.Fatalf("DELETE settings/live: %d %s", w.Code, w.Body.String())
	}
	if w := do(replicaA, "GET", attack, "", ""); w.Code != http.StatusOK {
		t.Errorf("after discarding, replica A should be back to the configured log mode: got %d %s", w.Code, w.Body.String())
	}
	waitFor(replicaB, http.StatusOK, "replica B did not go back to the configured mode")
}
