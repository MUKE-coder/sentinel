# Changelog

All notable changes to Sentinel are documented here.

## [2.3.0] - 2026-09-11

Settings, dashboard controls, and report sections that silently did
nothing now do what they say. The report sections that v2.2.2 admitted were
reading data nothing wrote have real data behind them, every report says
how far that data can be trusted, and dashboard config edits finally reach
the running middleware.

### Added

- **User activity is recorded.** `Config.UserExtractor` was never read, so
  no per-user activity was ever stored: the Users page, the GDPR report's
  per-user section, and anomaly detection (which only analyses activity) all
  saw nothing. When it is set, Sentinel now records one activity per
  authenticated request — the matched route pattern (no record IDs), method,
  status, duration, client IP, and, in WAF log mode, a link to the threat
  logged on that request. The extractor runs after the handler, so it can
  read whatever your auth middleware put on the context. Sentinel's own
  dashboard routes are not recorded.
- **Dashboard actions are audited.** Blocking and unblocking IPs, unlocking
  AuthShield users, changing WAF mode or rules, adding and deleting custom
  rules, changing alert severity or rate limits, resetting rate-limit
  counters, and resolving threats or marking false positives each write an
  audit entry: resource `sentinel.*`, the dashboard user as actor, role
  `sentinel_admin`, before/after state, and success or error. Before, an
  operator could switch the WAF to log-only or unblock an attacker without a
  trace.
- **Login attempts are audited.** Logins AuthShield observes on your app and
  logins to the dashboard are recorded under `Resource: "auth"`
  (`sentinel.AuditResourceAuth`), so the PCI-DSS report's `auth_events`
  section finally has data.
- **Report provenance.** Every report carries a `provenance` block: storage
  driver, whether it is durable, retention settings, the oldest stored threat
  and audit entry, and warnings whenever the data can't support the report —
  in-memory storage, a window longer than retention, a window that starts
  before the oldest record, an empty store, audit retention under PCI-DSS's
  12 months, no `UserExtractor`, and no source of `READ` audit entries.
- **`Storage.AuditRetentionDays`** (default 365). Audit logs keep their own
  retention; `RetentionDays` (default 90) no longer deletes them. The new
  `storage.AuditPruner` interface is implemented by the built-in stores.
- **`ValidateConfig`** flags anomaly detection without a `UserExtractor`
  (error — the detector never runs), negative retention (error — the cutoff
  lands in the future and deletes everything), audit retention under 12
  months (warning), and in-memory storage (warning).

### Settings that did nothing now do what they say

- **`WAF.Rules` sensitivity is enforced.** The per-category levels were
  never read — every pattern ran whatever they said. Now `off` disables a
  category, `low` keeps only the most precise patterns (confidence ≥ 80),
  `medium` drops the noisiest (< 60), and `strict` keeps all of them. The
  defaults keep every pattern the WAF ran before, so a default config
  detects exactly what it did; a category you had set to `off`, `low`, or
  `medium` now actually changes detection.
- **`WAFRule.Action: "log"` records without blocking.** A custom rule with
  Action `"log"` is recorded as a threat but never enforced, even in block
  mode, so a new rule can be watched against real traffic before it is
  trusted to block. A request that also trips an enforced rule is still
  blocked.
- **`RateLimit.Strategy` is honoured.** Every limit was a fixed window,
  whatever the config said. `sliding_window` (the default) now counts over
  the window ending now, so twice the limit can no longer pass in a moment
  either side of a window boundary; `fixed_window` and `token_bucket` are
  implemented too.
- **Dashboard config edits reach the running middleware.** Changing the WAF
  mode or rules (`PUT /api/waf/rules`), route rate limits
  (`PUT /api/rate-limits`), or the alert severity (`PUT /api/alerts/config`)
  updated only the API server's copy of the config — enforcement never
  changed, while the dashboard showed the new values. They now apply to
  live requests immediately (not persisted across a restart). New
  `middleware.NewWAF` with `SetMode` / `SetRules`,
  `RateLimiter.SetStrategy` / `SetRouteLimits` / `RouteLimits`, and
  `Dispatcher.SetMinSeverity` / `MinSeverity`.
- **Those endpoints validate their input.** An unknown WAF mode (which the
  WAF treated as log mode, blocking nothing), unknown sensitivity,
  non-positive window, route without a leading `/` or with an unmatchable
  pattern, unknown severity, or unknown custom-rule action now returns 400
  instead of being stored or silently skipped. A partial WAF update no
  longer resets the whole rule set. The WAF and rate-limit endpoints return
  409 when that feature isn't enabled.
- **`ValidateConfig`** reports an unknown `WAF.Mode` (error — nothing is
  blocked), unknown `WAF.Rules` levels, unknown custom-rule `Action`,
  unknown `RateLimit.Strategy`, and the deprecated `AI.DailySummary`.

### Deprecated

- **`AIConfig.DailySummary`** never did anything: nothing runs on a
  schedule, and the daily summary is generated on demand from the
  dashboard. `ValidateConfig` now warns when it is set.

### 🔥 Fix

- **SQLite / Postgres `ListUsers`, `GetAttackTrends`, `GetGeoStats`, and
  `GetTopTargets` were stubs** returning nothing, so the Users page and the
  attack-trend, geography, and top-target charts were empty on the default
  store. All four are implemented.
- **The memory store never pruned user activity**; it does now. Its audit
  log listing is sorted newest-first by timestamp, like the SQL stores.

### Behavior changes

- Compliance reports on in-memory storage in release mode return
  **409 `EPHEMERAL_STORAGE`** unless the request passes
  `?acknowledge_ephemeral=true`.
- Audit logs are kept 365 days by default instead of 90. The built-in stores'
  `Cleanup` no longer deletes audit entries; `PruneAuditLogs` does, on
  `AuditRetentionDays`. Budget for the extra rows on SQLite.
- With `UserExtractor` set, every authenticated request writes an activity
  row, alongside the per-request performance row Sentinel already writes.
- Rate limits are now a true sliding window by default: bursts straddling a
  window boundary are limited, and rejected requests no longer count
  against the client. Set `Strategy: sentinel.FixedWindow` for the old
  behavior. Rate-limit state (`GET /api/rate-limits/current`) now includes
  each counter's `limit` and `remaining`.
- Setting a `WAF.Rules` category to `off`, `low`, or `medium` now changes
  what the WAF detects.

## [2.2.2] - 2026-09-11

Security patch. Every fix below came out of verifying an external review of
Sentinel line by line. Upgrade if you run behind a reverse proxy
(`WAF.TrustedProxies` set), expose the dashboard, make outbound requests
with `sentinel.HTTPClient()` / `safefetch`, or hand compliance reports to
anyone.

### 🔒 Security

- **Client IP can no longer be spoofed through `X-Forwarded-For` behind a
  trusted proxy.** The first (leftmost) entry was used — but proxies such as
  nginx and Caddy *append* to the header, so the leftmost entry is whatever
  the client sent. Any client behind a trusted proxy could pick its own IP
  and slip per-IP rate limits, IP blocks, AuthShield lockouts, and threat
  attribution. The chain is now walked right to left, skipping
  `TrustedProxies`, and the first untrusted hop is the client. All header
  lines are read in order (a proxy may add its own line rather than extend
  the client's), `ip:port` and IPv4-mapped entries are normalised, and an
  unparseable header falls back to the proxy address instead of
  `X-Real-IP`. A dual-stack listener's `::ffff:a.b.c.d` peer address now
  matches IPv4 `TrustedProxies` entries.
- **Dashboard login and CSP-report rate limits key on the real client IP.**
  Both used gin's `c.ClientIP()`, which trusts `X-Forwarded-For` from every
  peer unless the host app called `SetTrustedProxies` — rotating the header
  gave a brute-forcer a fresh 10-attempt budget on every request. They now
  use the same trusted-proxy logic as the middleware, exported as
  `middleware.ClientIP(c)`.
- **SQL injection via `sort_by` on threat listings (SQLite / Postgres).** The
  dashboard API passed the query parameter into `ORDER BY` verbatim.
  Exploiting it needed a dashboard token, but outside release mode the
  default JWT secret makes tokens forgeable. `ThreatFilter.SortBy` is now
  allowlisted (`timestamp`, `severity`, `ip`, `path`); anything else falls
  back to `timestamp`.
- **SSRF client (`safefetch` / `sentinel.HTTPClient()`) closes several
  bypasses:**
  - `[::]` — the IPv6 unspecified address, which dials localhost like
    `0.0.0.0` — was allowed.
  - Newly denied: `192.0.0.0/24` (includes Oracle Cloud metadata
    `192.0.0.192`), `198.18.0.0/15`, `240.0.0.0/4` (incl. broadcast), IPv6
    multicast, Teredo (`2001::/32`), local-use NAT64 (`64:ff9b:1::/48`).
  - NAT64 (`64:ff9b::/96`) and 6to4 (`2002::/16`) addresses are judged by
    the IPv4 target they embed — `64:ff9b::a9fe:a9fe` reached
    `169.254.169.254`. Public targets stay reachable, so DNS64 on IPv6-only
    hosts keeps working.
  - Zoned IPv6 literals (`[fe80::1%25eth0]`) and IPv4-mapped literals
    (`[::ffff:127.0.0.1]`) never matched any range; both are normalised
    before the check.
  - Hostnames are compared without the DNS root dot, so
    `metadata.google.internal.` no longer dodges the metadata block;
    `metadata.goog` is blocked too.
  - The pre-flight DNS lookup honours the request context, and blocked
    redirects are reported to the pipeline like other blocks.

### 🔥 Fix

- **`safefetch` `AllowedHosts` works for internal hosts.** The connect-time
  guard never consulted it, so an allowed host that resolved to a private
  address passed validation and then failed at dial. Allowed hosts now skip
  the connect-time IP check, as documented.
- **Compliance reports compute correct numbers.**
  - PCI-DSS `blocked_threats` filtered on `resolved`, listing threats an
    operator had triaged rather than threats Sentinel blocked. It now
    filters on the new `ThreatFilter.Blocked`.
  - SOC 2 `total_threats_blocked` was counted from a one-row page, so it
    never exceeded 1; `total_threats_detected` counted only resolved
    threats. Both now come from the store's aggregate stats.
  - SOC 2 `total_events_processed` was threats + blocked + unique IPs — a
    sum that counted every blocked threat twice. It is now the number of
    threat events recorded in the window.
  - PCI-DSS summary counts and GDPR / SOC 2 totals come from store totals,
    so they stay exact when a listing hits its row cap; GDPR `access_count`
    counts all of a user's activity in the window, not the first 1000 rows.
- **Reports say when a list is partial.** Each report has a new `truncated`
  field naming the sections whose listing hit its row cap.

### Added

- `ThreatFilter.Blocked` (`*bool`) — filter threat listings by whether
  Sentinel blocked them. Supported by the memory, SQLite, and Postgres
  stores.
- `middleware.ClientIP(c)` — the trusted-proxy-aware client IP, for host
  code that needs to agree with Sentinel about who sent a request.

### Behavior changes

- Behind a trusted proxy, the recorded client IP for a request whose
  `X-Forwarded-For` carries client-supplied entries is now the address your
  proxy actually saw. Blocks and rate-limit counters that were keyed on
  spoofed addresses stop matching — which is the point.
- `safefetch` refuses the newly denied ranges. If you legitimately fetch
  from one, allow it with `AllowedCIDRs` or `AllowedHosts`.
- SOC 2 `total_events_processed` changed meaning (see above).

### Known gaps (planned for v2.3.0)

Some report sections still read data nothing writes: no built-in component
emits `READ` or `Resource: "auth"` audit entries (GDPR exports and PCI-DSS
auth events stay empty), the SQLite / Postgres `ListUsers` is a stub (GDPR
user access stays empty on the default store), and `Config.UserExtractor`
is never read, so no user activity is recorded and anomaly detection never
fires. These are fixed in v2.3.0; until then treat those sections as empty,
not clean.

## [2.2.1] - 2026-07-16

Fixes issue [#15](https://github.com/MUKE-coder/sentinel/issues/15): the GORM
audit plugin panicked on has-many and batch creates.

### 🔥 Fix

- **GORM plugin no longer panics on slice creates** (#15). When a record is
  created with a has-many association (`db.Create(&order)` where
  `order.Items` is a `[]Item`), GORM re-invokes the create callbacks for the
  association slice during `saveAssociations` — and `extractPrimaryKey` did
  a reflect field access that is only valid on structs, panicking with
  `reflect: call of reflect.Value.Field on slice Value`. Every has-many or
  batch create became a 500. Primary-key extraction is now kind-aware:
  - structs behave as before;
  - slices/arrays yield a comma-joined ID list (capped at 10, then
    `(+N more)`), so batch audit logs carry the batch's IDs;
  - pointers are dereferenced; map-based creates and other kinds safely
    yield an empty ResourceID instead of panicking.
- **Batch audit payloads are no longer dropped.** `modelToJSON` only handled
  JSON objects; slice payloads now wrap as `{"records": [...]}` so the audit
  log captures what was created.
- **All plugin callbacks are panic-guarded.** Auditing must never break the
  write it audits: a future bug in any Sentinel GORM callback is now
  recovered and logged instead of failing the host application's request.

## [2.2.0] - 2026-07-10

Issues #7, #8, #10, and #12 shared one failure mode: configuration that
compiles, reads as correct, and silently does nothing — discovered only as a
403 in production. v2.2.0 makes that class of bug detectable before deploy.

### Added

- **`sentinel.ValidateConfig(config) []ConfigIssue`** — inspects a config
  for entries that would be silently ignored or would silently disable a
  feature. Never rejects anything; it reports. Each `ConfigIssue` carries a
  severity (`IssueError` = a feature is dead or a control is disabled;
  `IssueWarning` = works but probably not intended), the config field, and
  a message explaining the runtime consequence. Checks cover:
  - unknown / unimplemented `Storage.Driver` values (silent fallback to
    in-memory storage — including the exported-but-unimplemented `MySQL`)
  - route patterns in `WAF.ExcludeRoutes`, `RateLimit.ExcludeRoutes`, and
    `RateLimit.ByRoute` keys that the matcher would drop (interior `**`,
    malformed globs) or that can never match (no leading `/`)
  - `WAF.TrustedProxies` entries that parse as neither IP nor CIDR
    (silently dropped today)
  - custom WAF rules: non-compiling regexes (silently dropped at mount),
    empty patterns (match **every** request — catastrophic in block mode),
    duplicate IDs (later rule silently replaces the earlier), and
    `AppliesTo` locations outside path/query/header/body (silently never
    scanned)
  - rate limiting enabled with no limits, `ByUser` without a
    `UserIDExtractor`, limits with zero requests or windows
  - AuthShield enabled without a `LoginRoute`; CAPTCHA tier unreachable
    because `CAPTCHAThreshold >= MaxFailedAttempts`
  - multiple CAPTCHA providers configured (only the first by precedence is
    used)
  - alert sinks missing their credentials (Slack/webhook URL, SMTP host,
    recipients, PagerDuty integration key — all silently skipped today)
  - `AIConfig` with a missing API key or unknown provider (silently
    disabled today)
  - IP reputation enabled without an AbuseIPDB key (checks silently
    return nothing)
  - insecure default dashboard credentials (warning; still fatal in
    release mode)
- **Mount / MountE run `ValidateConfig` automatically** and log each
  finding at startup — dead config is now visible in the boot log instead
  of surfacing as a 403 weeks later. Findings are never fatal; to gate a
  deploy, call `ValidateConfig` yourself and fail on `IssueError`.
- **`sentinel.NewRouteMatcher` / `sentinel.ValidateRoutePattern`
  re-exports** — assert your concrete production paths against your
  exclusion patterns in your own test suite (the workaround the #12
  reporter built by hand):

  ```go
  m := sentinel.NewRouteMatcher(cfg.WAF.ExcludeRoutes)
  if !m.Matches("/v1/payments/collect") {
      t.Fatal("payments endpoint is not excluded from the WAF")
  }
  ```

- **`middleware.ValidateRoutePattern(pattern) error`** — the single source
  of truth for pattern support, shared by `NewRouteMatcher` (which still
  warns and drops) and `ValidateConfig`. Returns errors wrapping the new
  `middleware.ErrUnsupportedPattern`.

### Compatibility

- No breaking changes. Zero-config `Mount` now logs two warnings about the
  built-in default credentials in dev mode — intended.

## [2.1.2] - 2026-07-10

Fixes issue [#12](https://github.com/MUKE-coder/sentinel/issues/12): the
route matcher introduced in v2.1.0 had its own silent-dead-config bug.

### 🐛 Fix

- **`/**` after a segment wildcard now actually matches** (#12). A pattern
  like `/api/apps/*/products/**` — the natural way to exclude a
  parameterised subtree, which is most REST paths — compiled into a literal
  string prefix containing `*`, matched nothing, and warned about nothing.
  Such patterns are now compiled to a segment-by-segment matcher: each
  segment is a `path.Match` glob consuming exactly one path segment, and the
  trailing `**` consumes any remainder including none, so the pattern
  matches `/api/apps/13/products` itself and everything below it. Plain
  subtree patterns (`/v1/**`) keep the cheap prefix compare. An interior
  `**` (not at the end) remains unsupported and is still rejected with a
  mount-time warning; malformed glob segments are likewise warned about and
  dropped rather than silently matching nothing.

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
