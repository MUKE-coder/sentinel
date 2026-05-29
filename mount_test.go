package sentinel_test

import (
	"errors"
	"testing"

	"github.com/MUKE-coder/sentinel"
	"github.com/gin-gonic/gin"
)

func TestMountE_RefusesDefaultPasswordInReleaseMode(t *testing.T) {
	prev := gin.Mode()
	gin.SetMode(gin.ReleaseMode)
	t.Cleanup(func() { gin.SetMode(prev) })

	r := gin.New()
	err := sentinel.MountE(r, nil, sentinel.Config{
		Storage: sentinel.StorageConfig{Driver: sentinel.Memory},
	})
	if !errors.Is(err, sentinel.ErrInsecureDefaults) {
		t.Fatalf("expected ErrInsecureDefaults, got %v", err)
	}
}

func TestMountE_AcceptsExplicitOptInInReleaseMode(t *testing.T) {
	prev := gin.Mode()
	gin.SetMode(gin.ReleaseMode)
	t.Cleanup(func() { gin.SetMode(prev) })

	r := gin.New()
	err := sentinel.MountE(r, nil, sentinel.Config{
		Storage: sentinel.StorageConfig{Driver: sentinel.Memory},
		Dashboard: sentinel.DashboardConfig{
			AllowInsecureDefaults: true,
		},
	})
	if err != nil {
		t.Fatalf("opt-in should allow defaults, got %v", err)
	}
}

func TestMountE_TestModeAllowsDefaults(t *testing.T) {
	// gin.TestMode (set by init in sentinel_test.go) should be permissive —
	// only release mode triggers the refusal.
	r := gin.New()
	if err := sentinel.MountE(r, nil, sentinel.Config{
		Storage: sentinel.StorageConfig{Driver: sentinel.Memory},
	}); err != nil {
		t.Fatalf("TestMode should tolerate defaults, got %v", err)
	}
}
