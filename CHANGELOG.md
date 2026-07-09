# Changelog

All notable changes to Sentinel are documented here.

## [2.1.1] - 2026-07-10

Follow-up to v2.1.0 for issue [#10](https://github.com/MUKE-coder/sentinel/issues/10):
the same class of false positive fixed for SSRF in v2.1.0 survived one regex
over, in `SQLi_Basic`.

### 🔥 Fix

- **SQLi patterns no longer match opaque tokens or scan headers** (#10).
  `SQLi_Basic` matched a bare `--` anywhere in the input, and SQLi patterns
  ran against `Cookie`/`Referer`/`User-Agent`. Base64url is `[A-Za-z0-9-_]`,
  so a ~400-character cookie holding two JWTs contains `--` with probability
  ≈ 9% — in `ModeBlock`, roughly one session in ten was 403'd at random, and
  the verdict changed on every token refresh. Three-part fix:
  - `--` only matches as a statement terminator (followed by whitespace or
    end of input), the way `SQLi_Comment` already required.
  - `0x` + hex must not start mid-word, so hex sequences inside base64 text
    no longer match.
  - Every remaining pattern is now explicitly location-scoped: SQLi,
    command-injection → query + body; path-traversal → path + query + body.
    XSS keeps header scanning (reflected-Referer XSS is real, and markup
    doesn't occur naturally in headers) but is now scoped explicitly too —
    no pattern relies on the implicit "empty means everywhere" default
    anymore, so a future pattern can't silently inherit scan-everything.
  - Regression tests pin JWT-bearing cookies, `0x`-hex ids, double-hyphen
    SEO slugs (in Referer and in query values), and header-borne
    SQL/shell-shaped prose as clean, plus the real payload shapes
    (`1' OR 1=1--`, `;-- `, `0x4142...`) as still detected.

## [2.1.0] - 2026-07-10

Emergency-priority fix release for issues [#7](https://github.com/MUKE-coder/sentinel/issues/7)
and [#8](https://github.com/MUKE-coder/sentinel/issues/8), which together took
down a production deployment: the WAF's SSRF pattern matched the version
string of every stable-channel browser, and the wildcard route exclusions
that would have contained the blast radius were silently ignored.

**If you run `WAF.Mode = ModeBlock`, upgrade immediately.**

### 🔥 Critical fix

- **WAF no longer blocks Chrome/Edge/Brave users** (#8). The SSRF rule's IP
  alternatives were unanchored, so `0.0.0.0` matched inside
  `Chrome/140.0.0.0` and `10.x.x.x` inside `110.0.0.0` — in `ModeBlock`,
  every request from a browser whose major version ends in zero got a 403.
  Two-part fix:
  - Internal-host tokens are now **anchored**: they only match as a
    standalone token or URL host, never inside a longer dotted number.
    Bare `::1` now requires brackets (`[::1]`).
  - Patterns are now **scoped to the locations where the vulnerability
    class actually lives** (new `Locations` field on detection patterns).
    SSRF, XXE, and prototype-pollution patterns scan query + body only;
    open-redirect scans query only (Referer headers legitimately embed
    full URLs); LFI scans path + query + body. SQLi, XSS, path-traversal
    and command-injection patterns still scan headers.
  - Regression tests pin Chrome 110–200 User-Agents so this cannot
    silently recur each time Chrome reaches a version ending in zero.

### 🔐 Security fixes

- **WebSocket endpoints now require a valid JWT.** `/ws/threats`,
  `/ws/metrics`, and `/ws/alerts` previously validated the token only when
  one was supplied — an unauthenticated client could subscribe to the live
  threat feed (attacker IPs, matched payloads, request paths). The embedded
  dashboard always sent the token, so no dashboard change is needed.
- **Dashboard login uses constant-time credential comparison**
  (`crypto/subtle`) instead of `!=`.
- **Dashboard IP blocks are bounded by default** (#8). "Block IP" /
  "Block actor" now default to a **24-hour expiry**; a permanent block
  requires an explicit `"permanent": true` in the request. Previously one
  click wrote `expires_at = NULL` — permanent, restart-surviving, and
  catastrophic for CGNAT egress IPs. Responses now include `expires_at`.

### 🐛 Fixes

- **Wildcard route patterns actually match** (#7, #8). One shared matcher
  now backs `WAF.ExcludeRoutes` and `RateLimit.ByRoute`:
  - exact: `/health`
  - trailing wildcard: `/v1/*` or `/v1/**` (both match `/v1` and
    everything under `/v1/`)
  - segment glob: `/api/apps/*/products` (`path.Match` semantics)
  Previously entries containing `*` were silent dead code in both configs —
  release-notes call-out: any `/v1/**` entry you shipped has had WAF
  inspection / no route limit on those paths the whole time.
  `RateLimit.ExcludeRoutes` keeps its historical prefix behavior for plain
  entries and additionally supports the wildcard shapes. Wildcard `ByRoute`
  counters are shared per pattern (per client IP), so rotating sub-paths
  can't reset a budget; an exact key wins over a pattern.
- **AuthShield survives path rewrites** (#8). The login route is matched
  against the registered route pattern (`c.FullPath()`) as well as
  `URL.Path`, so upstream middleware that rewrites the path can no longer
  silently disable brute-force protection. Parameterized login routes
  (`/login/:tenant`) can now be configured by their registered pattern.
- **No more per-request blocklist DB query** (#8). `Mount` wires the WAF to
  the IP manager's in-memory cache (synced every 30 s, updated immediately
  on block/unblock), removing one storage round trip from the hot path —
  and CIDR blocks now take effect in the WAF, which the old exact-match
  query never honored. Direct `middleware.WAFMiddleware` callers can pass
  the new optional `IPBlockChecker`; without one, the storage fallback now
  **logs lookup failures** (throttled 1/min) instead of silently failing
  open.

### 📣 Operational visibility

- **Storage-target warning** (#8): if you pass a `*gorm.DB` but leave
  `Storage` unset, Mount now warns loudly that security data goes to the
  `sentinel.db` SQLite file, not your database — the `db` parameter only
  wires audit-log capture.
- **Reverse-proxy misconfiguration warning** (#8): if requests carry
  `X-Forwarded-For` / `X-Real-IP` while `WAF.TrustedProxies` is empty,
  Sentinel logs a one-time warning that per-IP blocks, rate limits, and
  threat attribution are keying on the proxy address.
- Invalid or unsupported route patterns (e.g. `**` mid-pattern) are logged
  at mount instead of matching nothing silently.

### Compatibility

- No breaking API changes. `middleware.WAFMiddleware` gained an optional
  variadic parameter; all existing call sites compile unchanged.
- Behavior changes to review before upgrading:
  - Dashboard blocks now expire after 24 h unless `"permanent": true`.
  - WebSocket connections without a token are rejected (the embedded
    dashboard is unaffected).
  - Wildcard `ExcludeRoutes` / `ByRoute` entries that were previously dead
    now take effect — audit yours before deploying.

## [2.0.1] - 2026-05-29

Follow-up to v2.0.0 that closes the only gap shipped with the main release:
dedicated dashboard pages for the two new features that previously only
showed up in the generic threats feed.

### Added

- **Dashboard page: `/sentinel/ui/csp`** — Browser-reported CSP violations
  as a first-class view. Top-of-page stat strip (total, distinct directives,
  distinct blocked URIs), a "top blocked URIs grouped by directive"
  aggregate panel, and a paginated list with a detail modal that breaks out
  source-file / line / column / script-sample. Live-updates via the threats
  WebSocket.
- **Dashboard page: `/sentinel/ui/auth-shield`** — Live AuthShield state.
  Counts of locked / CAPTCHA-tier / warming IPs, full table of per-IP
  failure counts and lock expiry, and an inline tip when no CAPTCHA
  provider is configured. Auto-refreshes every 10 seconds.
- **`GET /sentinel/api/auth-shield/status`** — JSON snapshot of the
  AuthShield's in-memory per-IP state plus the configured CAPTCHA provider
  name. Returns `{enabled: false}` when AuthShield is off so the page can
  render a useful empty state.
- **`GET /sentinel/api/csp-violations/stats`** — Server-side aggregation of
  CSP violations grouped by `(violated_directive, blocked_uri)`. The
  dashboard's "top blocked" panel consumes this.

### Notes

- `middleware.AuthShield.Snapshot()` is now exported. Useful if you build
  your own dashboard against the same data.

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
