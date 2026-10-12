package sentinel

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// A driver Mount cannot honour must be an error. Falling back to in-memory
// storage is what hid a misspelled driver and an unimplemented MySQL: the
// dashboard looked healthy and every threat, block, and audit entry vanished
// on restart (issue #30).
func TestMountE_RefusesUnknownStorageDriver(t *testing.T) {
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	defer gin.SetMode(prev)

	for _, driver := range []StorageDriver{"postgress", "mongodb", "sqlite3"} {
		t.Run(string(driver), func(t *testing.T) {
			err := MountE(gin.New(), nil, Config{
				Storage:   StorageConfig{Driver: driver, DSN: "whatever"},
				Dashboard: DashboardConfig{Password: "pw", SecretKey: "secret"},
			})
			if err == nil {
				t.Fatal("an unknown driver must be an error, not a silent fall back to memory")
			}
			if !strings.Contains(err.Error(), string(driver)) {
				t.Errorf("the error should name the driver, got: %v", err)
			}
		})
	}
}

// MySQL is a real driver now, so an unreachable server is a startup error
// rather than a silent in-memory store.
func TestMountE_MySQLConnectionFailureIsAnError(t *testing.T) {
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	defer gin.SetMode(prev)

	err := MountE(gin.New(), nil, Config{
		Storage:   StorageConfig{Driver: MySQL, DSN: "sentinel:sentinel@tcp(127.0.0.1:1)/sentinel?parseTime=True"},
		Dashboard: DashboardConfig{Password: "pw", SecretKey: "secret"},
	})
	if err == nil {
		t.Fatal("an unreachable MySQL must fail the mount")
	}
	if !strings.Contains(err.Error(), "MySQL") {
		t.Errorf("the error should say MySQL, got: %v", err)
	}
}

// TestMountE_OnMySQL mounts Sentinel on a real MySQL when SENTINEL_MYSQL_DSN
// is set, and checks the parts that need durable storage: an IP block
// written through the dashboard API is enforced, and the audit entry for it
// is stored and chains.
//
//	docker run -d --name sentinel-mysql -e MYSQL_ROOT_PASSWORD=pw \
//	  -e MYSQL_DATABASE=sentinel -p 3306:3306 mysql:8
//	SENTINEL_MYSQL_DSN='root:pw@tcp(127.0.0.1:3306)/sentinel?charset=utf8mb4&parseTime=True' \
//	  go test -run TestMountE_OnMySQL .
func TestMountE_OnMySQL(t *testing.T) {
	dsn := os.Getenv("SENTINEL_MYSQL_DSN")
	if dsn == "" {
		t.Skip("set SENTINEL_MYSQL_DSN to run the MySQL mount test")
	}
	prev := gin.Mode()
	gin.SetMode(gin.TestMode)
	defer gin.SetMode(prev)

	r := gin.New()
	cfg := Config{
		Storage:   StorageConfig{Driver: MySQL, DSN: dsn},
		Dashboard: DashboardConfig{Password: "correct-horse-battery", SecretKey: "mysql-secret"},
	}
	if err := MountE(r, nil, cfg); err != nil {
		t.Fatalf("MountE on MySQL: %v", err)
	}
	r.GET("/api/items", func(c *gin.Context) { c.Status(http.StatusOK) })

	do := func(method, path, token, body, ip string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.RemoteAddr = ip + ":5000"
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		return w
	}

	w := do("POST", "/sentinel/api/auth/login", "", `{"username":"admin","password":"correct-horse-battery"}`, "192.0.2.1")
	var login struct {
		Token string `json:"token"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &login) != nil {
		t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}

	blocked := "198.51.100." + strconv.Itoa(time.Now().Second()%250+1)
	if w := do("POST", "/sentinel/api/ip/block", login.Token, `{"ip":"`+blocked+`","reason":"mysql test"}`, "192.0.2.1"); w.Code != http.StatusOK {
		t.Fatalf("block: %d %s", w.Code, w.Body.String())
	}
	if code := do("GET", "/api/items", "", "", blocked).Code; code != http.StatusForbidden {
		t.Errorf("a blocked IP must get 403 with MySQL storage, got %d", code)
	}

	w = do("GET", "/sentinel/api/audit-logs/verify", login.Token, "", "192.0.2.1")
	if w.Code != http.StatusOK {
		t.Fatalf("audit verify: %d %s", w.Code, w.Body.String())
	}
	var verify struct {
		Data struct {
			OK      bool `json:"ok"`
			Checked int  `json:"checked"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &verify); err != nil {
		t.Fatalf("decode verify: %v", err)
	}
	if verify.Data.Checked == 0 {
		t.Error("the block should have been audited and stored in MySQL")
	}
	if !verify.Data.OK {
		t.Error("the audit chain stored in MySQL must verify")
	}
}
