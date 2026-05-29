package captcha

import (
	"context"
	"errors"
	"strconv"
	"strings"
	"testing"
)

func TestSelfHosted_RoundTrip(t *testing.T) {
	secret := "test-secret"
	ch, err := IssueSelfHostedChallenge(secret)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	// Question is "a + b = ?" — extract the correct answer baked into the ID.
	parts := strings.Split(ch.ID, ".")
	if len(parts) != 4 {
		t.Fatalf("issued token shape unexpected: %q", ch.ID)
	}
	correct := parts[1]
	token := ch.ID + "." + correct

	p := NewSelfHostedProvider(secret)
	if err := p.Verify(context.Background(), token, ""); err != nil {
		t.Fatalf("verify good token: %v", err)
	}
}

func TestSelfHosted_WrongAnswer(t *testing.T) {
	secret := "test-secret"
	ch, _ := IssueSelfHostedChallenge(secret)
	parts := strings.Split(ch.ID, ".")
	correct, _ := strconv.Atoi(parts[1])
	wrong := strconv.Itoa(correct + 1)

	p := NewSelfHostedProvider(secret)
	if err := p.Verify(context.Background(), ch.ID+"."+wrong, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid for wrong answer, got %v", err)
	}
}

func TestSelfHosted_BadSignature(t *testing.T) {
	ch, _ := IssueSelfHostedChallenge("real-secret")
	parts := strings.Split(ch.ID, ".")
	token := ch.ID + "." + parts[1]

	p := NewSelfHostedProvider("wrong-secret")
	if err := p.Verify(context.Background(), token, ""); !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid with wrong secret, got %v", err)
	}
}
