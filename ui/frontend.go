// Package ui provides the embedded React dashboard for Sentinel.
// Built assets are embedded into the Go binary using //go:embed.
package ui

import (
	"embed"
	"io/fs"
)

//go:embed dist
var distFS embed.FS

// DistFS returns a sub-filesystem rooted at the dist directory.
func DistFS() (fs.FS, error) {
	return fs.Sub(distFS, "dist")
}
