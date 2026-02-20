# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Sentinel, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, please email security concerns with:

1. A description of the vulnerability
2. Steps to reproduce
3. The potential impact
4. Any suggested fixes (optional)

We will acknowledge receipt within 48 hours and provide a timeline for a fix.

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest  | Yes       |

## Security Considerations

### Dashboard Authentication

- The dashboard uses JWT (HMAC-SHA256) tokens for authentication
- Tokens are stored in React state only (never localStorage or cookies)
- Always set a strong `SecretKey` in production — the default is auto-generated per process restart
- Change the default username/password in production deployments

### WAF Limitations

- The WAF uses regex-based pattern matching, which can be bypassed by sophisticated attackers
- It is designed as a defense-in-depth layer, not a standalone security solution
- Always validate and sanitize input in your application code as well

### Storage

- SQLite databases should have appropriate file permissions
- The `sentinel.db` file contains security event data — protect it accordingly
- Use the `RetentionDays` configuration to limit data retention

### Rate Limiting

- Rate limit state is stored in-memory and is lost on process restart
- In multi-instance deployments, each instance maintains independent rate limit counters

### AI Integration

- API keys for AI providers are stored in memory only (passed via config)
- AI responses are cached in-memory with TTL expiration
- Never log or expose AI provider API keys
