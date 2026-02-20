package alerting

import (
	"context"
	"fmt"
	"net/smtp"
	"strings"
	"time"

	sentinel "github.com/MUKE-coder/sentinel/core"
)

// EmailProvider sends alerts via SMTP email.
type EmailProvider struct {
	config sentinel.EmailConfig
}

// NewEmailProvider creates a new email alert provider.
func NewEmailProvider(config sentinel.EmailConfig) *EmailProvider {
	return &EmailProvider{config: config}
}

// Name returns "email".
func (e *EmailProvider) Name() string {
	return "email"
}

// Send sends a threat alert via email.
func (e *EmailProvider) Send(ctx context.Context, te *sentinel.ThreatEvent) error {
	if e.config.SMTPHost == "" || len(e.config.Recipients) == 0 {
		return fmt.Errorf("email: SMTP host or recipients not configured")
	}

	subject := formatEmailSubject(te)
	body := formatEmailBody(te)

	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: %s\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		e.config.Username,
		strings.Join(e.config.Recipients, ","),
		subject,
		body,
	)

	addr := fmt.Sprintf("%s:%d", e.config.SMTPHost, e.config.SMTPPort)
	auth := smtp.PlainAuth("", e.config.Username, e.config.Password, e.config.SMTPHost)

	return smtp.SendMail(addr, auth, e.config.Username, e.config.Recipients, []byte(msg))
}

func formatEmailSubject(te *sentinel.ThreatEvent) string {
	types := strings.Join(te.ThreatTypes, ", ")
	return fmt.Sprintf("[Sentinel] %s Threat: %s from %s", te.Severity, types, te.IP)
}

func formatEmailBody(te *sentinel.ThreatEvent) string {
	types := strings.Join(te.ThreatTypes, ", ")
	blockedStr := "No"
	if te.Blocked {
		blockedStr = "Yes"
	}

	location := te.IP
	if te.Country != "" {
		location = fmt.Sprintf("%s (%s)", te.IP, te.Country)
	}

	return fmt.Sprintf(`<html><body style="font-family:sans-serif;background:#0a0f1e;color:#e0e0e0;padding:20px;">
<h2 style="color:#ff2d55;">%s Threat Detected</h2>
<table style="border-collapse:collapse;">
<tr><td style="padding:4px 12px;color:#8892a0;">Type</td><td style="padding:4px 12px;">%s</td></tr>
<tr><td style="padding:4px 12px;color:#8892a0;">IP</td><td style="padding:4px 12px;">%s</td></tr>
<tr><td style="padding:4px 12px;color:#8892a0;">Route</td><td style="padding:4px 12px;">%s %s</td></tr>
<tr><td style="padding:4px 12px;color:#8892a0;">Blocked</td><td style="padding:4px 12px;">%s</td></tr>
<tr><td style="padding:4px 12px;color:#8892a0;">Time</td><td style="padding:4px 12px;">%s</td></tr>
</table>
</body></html>`,
		te.Severity, types, location, te.Method, te.Path, blockedStr,
		te.Timestamp.UTC().Format(time.RFC3339))
}
