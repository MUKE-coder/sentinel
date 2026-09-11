package core

import (
	"crypto/rand"
	"encoding/hex"
)

// randomSecretKey returns a fresh 256-bit JWT signing secret. ApplyDefaults
// uses it when Dashboard.SecretKey is unset, so a zero-config deployment never
// signs tokens with a secret published in the source code. The cost is that
// dashboard sessions end on every restart and aren't accepted across
// replicas; set SecretKey to keep them.
func randomSecretKey() string {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand does not fail on supported platforms; if it ever does,
		// refusing to start beats signing tokens with a guessable key.
		panic("sentinel: generating a dashboard secret: " + err.Error())
	}
	return hex.EncodeToString(b)
}
