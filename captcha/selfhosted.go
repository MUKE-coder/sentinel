package captcha

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SelfHostedChallenge is an issued arithmetic challenge the user must solve
// and return as a token. Designed for projects that want a CAPTCHA tier
// without adding a third-party dependency.
type SelfHostedChallenge struct {
	ID        string `json:"id"`
	Question  string `json:"question"`
	ExpiresAt int64  `json:"expires_at"`
}

// IssueSelfHostedChallenge produces a fresh arithmetic challenge plus the
// signing-aware ID the client must echo back along with their answer.
//
// Token returned by the client: "<id>.<answer>.<signature>" base64-url
// encoded.
func IssueSelfHostedChallenge(secret string) (SelfHostedChallenge, error) {
	if secret == "" {
		return SelfHostedChallenge{}, errors.New("captcha: empty secret")
	}
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return SelfHostedChallenge{}, err
	}
	a := int(buf[0])%9 + 1
	b := int(buf[1])%9 + 1
	answer := a + b
	expiresAt := time.Now().Add(2 * time.Minute).Unix()

	id := base64.RawURLEncoding.EncodeToString(buf[:])
	mac := hmac.New(sha256.New, []byte(secret))
	expBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(expBytes, uint64(expiresAt))
	mac.Write([]byte(id))
	mac.Write([]byte(strconv.Itoa(answer)))
	mac.Write(expBytes)
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// Embed answer + expiry into the id so the verifier doesn't need state.
	token := fmt.Sprintf("%s.%d.%d.%s", id, answer, expiresAt, sig)

	return SelfHostedChallenge{
		ID:        token,
		Question:  fmt.Sprintf("%d + %d = ?", a, b),
		ExpiresAt: expiresAt,
	}, nil
}

// verifySelfHostedToken parses and validates a token of shape produced by
// IssueSelfHostedChallenge plus the user's claimed answer in the last segment.
// Expected token: "<id>.<correct-answer>.<expires-at>.<sig>.<user-answer>"
func verifySelfHostedToken(secret, token string) error {
	parts := strings.Split(token, ".")
	if len(parts) != 5 {
		return errors.New("malformed token")
	}
	id, correctStr, expStr, sig, userStr := parts[0], parts[1], parts[2], parts[3], parts[4]

	expiresAt, err := strconv.ParseInt(expStr, 10, 64)
	if err != nil {
		return errors.New("bad expiry")
	}
	if time.Now().Unix() > expiresAt {
		return errors.New("expired")
	}

	expBytes := make([]byte, 8)
	binary.BigEndian.PutUint64(expBytes, uint64(expiresAt))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(id))
	mac.Write([]byte(correctStr))
	mac.Write(expBytes)
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return errors.New("bad signature")
	}

	if correctStr != userStr {
		return errors.New("wrong answer")
	}
	return nil
}
