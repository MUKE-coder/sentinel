# Changelog

All notable changes to Sentinel are documented here.

## [2.0.0] - 2026-05-29

A security + architecture sweep. v2 closes four trivially-exploitable holes
that shipped in v1, refactors `Mount` so library failures don't kill the
host process, and lands four community-requested security features.

### ⚠️ Breaking changes

1. **`Mount` no longer accepts default credentials in `gin.ReleaseMode`.**
   In release mode, `Mount` aborts with `ErrInsecureDefaults` if
   `Dashboard.Password == DefaultInsecurePassword` or
   `Dashboard.SecretKey == DefaultInsecureSecretKey`. Set those fields,
   or opt-in via `Dashboard.AllowInsecureDefaults = true` (dev only).
2. **`MountE(router, db, config) error` is the new recommended entry point.**
   `Mount` still exists and still `log.Fatalf`s on error for backwards
   compatibility, but `MountE` lets library callers handle failures
   themselves instead of having Sentinel kill the host process.
3. **`X-Forwarded-For` is ignored by default.** Previously, any caller could
   spoof their source IP. The new `WAFConfig.TrustedProxies` CIDR allowlist
   gates XFF / X-Real-IP — only requests originating from a listed proxy
   have their proxy headers honored. Empty list = ignore them entirely
   (the safe default).
4. **`middleware.WAFMiddleware` takes `*detection.CustomRuleEngine` as a
   typed fourth parameter** instead of `...*detection.CustomRuleEngine`.
   Pass `nil` when no custom engine is configured.
5. **`storage.Store` is now a composition** of focused sub-interfaces
   (`ThreatStore`, `ActorStore`, `IPStore`, `AuditStore`, `MetricStore`,
   `UserActivityStore`, `AnalyticsStore`, `ScoreStore`, `LifecycleStore`).
   Existing implementations are unchanged; downstream code that only
   needed one capability can now depend on a smaller interface.
6. **`db *gorm.DB` is finally wired.** When non-nil, `Mount` / `MountE`
   auto-registers the GORM audit plugin. Previously the parameter was
   ignored and users had to call `db.Use(sentinelgorm.New(pipe))`
   themselves — the signature lied.

### 🔐 Security fixes

- **Defaults refuse in production.** Stops zero-config deployments from
  shipping with forgeable admin tokens against the known default secret.
- **XFF trust closed.** `WAFConfig.TrustedProxies` CIDR allowlist gates
  proxy headers; spoofing-by-header bypass of IP blocks and rate limits
  is closed.
- **WAF body-inspection bypass closed.** `WAFConfig.MaxBodyBytes` (default
  64 KB) and `WAFConfig.RejectOversizedBody`. Attackers can no longer
  pad junk to slip a payload past byte 10240.
- **`ActorIDFromIP` is SHA-256 based and IPv6-safe.** Replaces the
  `"actor_" + replaceAll(".", "_")` scheme that collided for v6 and
  leaked IPs.

### ✨ New features

- **CVSS on every `ThreatEvent`.** Severity score (0.0–10.0) plus the
  canonical CVSS:3.1 vector, populated automatically from the threat type
  via `core.DefaultCVSSForTypes`. Surfaces in the dashboard, the
  generic-webhook payload, and PagerDuty `custom_details`. Closes #5.
- **PagerDuty alert sink.** `AlertConfig.PagerDuty` with `MinSeverity` +
  `MinCVSS` filters so ops can fill the dashboard at `MinSeverity=High`
  while paging only on `MinCVSS>=9.0`. Closes #5.
- **`sentinel.HTTPClient(opts...)` — SSRF-hardened `*http.Client`.**
  Policy enforced at request build, redirect, and TCP connect time
  (DNS-rebinding TOCTOU closed via `net.Dialer.Control`). Default denylist
  covers loopback, link-local, CGNAT, RFC1918, AWS IMDS (169.254.169.254),
  cloud-metadata hostnames, IPv6 ULA, and the AWS IPv6 metadata range.
  Blocked attempts can be reported into the Sentinel pipeline so SSRF
  events surface in the dashboard. Closes #3.
- **CSP violation receiver — `POST /sentinel/csp-report`.** Accepts both
  legacy `application/csp-report` and modern `application/reports+json`,
  applies a per-IP 100/min rate limit (CSP reports CAN be hostile), emits
  through the existing pipeline as `ThreatType=CSPViolation`. Pair with
  `middleware.CSPMiddleware` for the header. Closes #2.
- **CAPTCHA tier on AuthShield.** Crossing `AuthShieldConfig.CAPTCHAThreshold`
  (default `MaxFailedAttempts / 2`) requires a CAPTCHA on the next login.
  Built-in providers: hCaptcha, Cloudflare Turnstile, Google reCAPTCHA v2,
  and a self-hosted HMAC-signed arithmetic challenge for no-third-party
  setups. Closes #4.
- **AI daily call cap.** `AIConfig.MaxCallsPerDay` (default 500) caps
  total LLM calls across all AI features. Returns `ai.ErrBudgetExhausted`
  so callers degrade gracefully. Cache wraps inside budget so cached hits
  don't burn quota.
- **Pipeline drop visibility.** `Pipeline.DroppedCount()` /
  `EmittedCount()` and `pipeline_dropped` / `pipeline_emitted` on
  `GET /sentinel/api/performance/overview` so operators see when an
  attack is overwhelming the buffer.
- **Postgres adapter is real.** Previously a stub that silently fell
  through to in-memory storage. Now wired through GORM with the same
  models the SQLite adapter uses; `SENTINEL_TEST_PG_DSN` runs the
  smoke test.

### 🐛 Fixes

- WAF `ModeLog` no longer races the pipeline worker on `StatusCode` — the
  event is now emitted *after* `c.Next()` completes.

### 🧭 Migration

```diff
- sentinel.Mount(r, nil, sentinel.Config{
-     Dashboard: sentinel.DashboardConfig{},
- })
+ if err := sentinel.MountE(r, db, sentinel.Config{
+     Dashboard: sentinel.DashboardConfig{
+         Password:  os.Getenv("SENTINEL_PASSWORD"),
+         SecretKey: os.Getenv("SENTINEL_JWT_SECRET"),
+     },
+     WAF: sentinel.WAFConfig{
+         Enabled:        true,
+         TrustedProxies: []string{"10.0.0.0/8"},
+     },
+ }); err != nil {
+     log.Printf("[sentinel] mount failed: %v — running without security layer", err)
+ }
```

If you previously called `WAFMiddleware(cfg, store, pipe)` directly,
change to `WAFMiddleware(cfg, store, pipe, nil)`.

---

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
