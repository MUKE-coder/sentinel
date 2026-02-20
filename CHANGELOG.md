# Changelog

All notable changes to Sentinel are documented here.

## [0.1.0] - 2025-02-20

### Added

#### Core (Phase 1)
- `sentinel.Mount()` single-call setup for Gin routers
- Web Application Firewall (WAF) with SQL injection, XSS, path traversal, command injection, SSRF, XXE detection
- Multi-dimensional rate limiting (per-IP, per-user, per-route, global) with sliding windows
- Security headers middleware (CSP, HSTS, X-Frame-Options, Referrer-Policy, Permissions-Policy)
- Performance monitoring middleware with per-route latency tracking (p50/p95/p99)
- Async event pipeline with ring buffer (10K capacity, configurable workers)
- Storage interface with in-memory and pure-Go SQLite backends
- REST API with JWT authentication (HMAC-SHA256)
- WebSocket support for live threat and metrics streaming
- Embedded React dashboard with dark theme (React 18 + Vite + TailwindCSS)
- Zero-config defaults — `sentinel.Config{}` works out of the box

#### Intelligence (Phase 2)
- Threat actor profiling with automatic risk scoring
- IP management (whitelist/blacklist) with CIDR support
- Security score engine with 5-dimension weighted scoring
- Geolocation for IP-based geographic attribution
- IP reputation checking
- Auth shield for brute-force protection with automatic lockouts
- Custom WAF rule engine with regex patterns
- GORM audit logging plugin for automatic database change tracking

#### Alerting & Reports (Phase 3)
- Alert dispatching to Slack, email, and webhooks
- Configurable alert severity thresholds
- Anomaly detection with configurable sensitivity levels
- GDPR compliance report generation
- PCI-DSS compliance report generation
- SOC 2 compliance report generation

#### AI & Analytics (Phase 4)
- AI provider interface with Claude, OpenAI, and Gemini implementations
- AI-powered threat analysis and actor assessment
- Natural language security queries
- AI-generated daily summaries and WAF recommendations
- Cached AI responses with TTL expiration
- Advanced analytics with attack trends, geographic distribution, time patterns
- Rate limit dashboard with live state monitoring
- Compliance report dashboard with JSON export
- Analytics dashboard with Recharts visualizations
