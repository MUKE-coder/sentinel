import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';

export const metadata = {
  title: "What's New in v2.0.0 - Sentinel Docs",
  description:
    'Sentinel v2.0.0 release notes — MountE, TrustedProxies, body inspection cap, CVSS scoring, PagerDuty sink, SSRF-hardened HTTPClient, CSP report endpoint, CAPTCHA tier, real Postgres adapter, and a migration guide.',
  alternates: {
    canonical: 'https://sentinel-go-sdk.vercel.app/docs/whats-new-v2',
  },
  openGraph: {
    title: "What's New in v2.0.0 - Sentinel Docs",
    description:
      'Sentinel v2.0.0 release notes and migration guide. Security hardening, CVSS, PagerDuty, SSRF guard, CSP receiver, CAPTCHA tier.',
    url: 'https://sentinel-go-sdk.vercel.app/docs/whats-new-v2',
    type: 'article',
  },
};

export default function WhatsNewV2() {
  return (
    <>
      <h1>What's New in v2.0.0</h1>
      <p>
        v2 is a security + architecture sweep. It closes four trivially-exploitable defaults
        that shipped in v1, refactors <code>Mount</code> so library failures no longer kill the
        host process, and lands four community-requested features (CVSS scoring + PagerDuty,
        SSRF-hardened HTTP client, CSP violation receiver, CAPTCHA tier on AuthShield).
      </p>

      <Callout type="warning" title="Breaking changes">
        v2 introduces several breaking changes. The summary is in this page; full details and a
        migration diff live in <a href="https://github.com/MUKE-coder/sentinel/blob/main/CHANGELOG.md">CHANGELOG.md</a>.
      </Callout>

      <h2>1. Defaults refuse in production</h2>
      <p>
        In <code>gin.ReleaseMode</code>, Sentinel now aborts startup if you're still using the
        built-in default password or JWT secret. The previous behavior — accept a published
        default and let anyone forge admin tokens — was a footgun. Opt back in only for dev.
      </p>
      <CodeBlock
        language="go"
        code={`sentinel.Config{
    Dashboard: sentinel.DashboardConfig{
        Password:  os.Getenv("SENTINEL_PASSWORD"),
        SecretKey: os.Getenv("SENTINEL_JWT_SECRET"),

        // Dev-only escape hatch:
        // AllowInsecureDefaults: true,
    },
}`}
      />

      <h2>2. <code>MountE</code> returns an error</h2>
      <p>
        Library callers who don't want a Sentinel-init failure to <code>log.Fatalf</code> the
        host process should now use <code>MountE</code>. The old <code>Mount</code> remains for
        backwards compatibility — it just calls <code>MountE</code> and fatal-logs on error.
      </p>
      <CodeBlock
        language="go"
        code={`if err := sentinel.MountE(r, db, cfg); err != nil {
    log.Printf("sentinel disabled: %v", err)
    // App keeps running without the security layer
}`}
      />

      <h2>3. X-Forwarded-For trust requires opt-in</h2>
      <p>
        Previously any attacker could send <code>X-Forwarded-For: 8.8.8.8</code> and spoof their
        source IP, bypassing IP blocks and per-IP rate limits. v2 ignores proxy headers unless
        the direct connection originates from a configured trusted proxy.
      </p>
      <CodeBlock
        language="go"
        code={`WAF: sentinel.WAFConfig{
    Enabled: true,
    TrustedProxies: []string{
        "10.0.0.0/8",
        "172.16.0.0/12",
        // Your load balancer's CIDR
    },
},`}
      />

      <h2>4. WAF body-inspection cap</h2>
      <p>
        The old WAF inspected the first 10 KB of every request body, then attached the
        <em>full</em> body to the handler. Attackers could pad 10 KB of junk and hide the payload
        at byte 10241. v2 introduces a configurable cap and an optional hard reject.
      </p>
      <CodeBlock
        language="go"
        code={`WAF: sentinel.WAFConfig{
    MaxBodyBytes:        128 * 1024, // default 64 KB
    RejectOversizedBody: true,        // return 413 instead of inspecting partial
},`}
      />

      <h2>5. CVSS on every ThreatEvent + PagerDuty sink</h2>
      <p>
        Every <code>ThreatEvent</code> now carries a CVSS 3.1 score and canonical vector, picked
        automatically from the threat type. Use <code>AlertConfig.PagerDuty</code> with
        <code>MinCVSS</code> to page only on the worst.
      </p>
      <CodeBlock
        language="go"
        code={`Alerts: sentinel.AlertConfig{
    MinSeverity: sentinel.SeverityHigh, // fills dashboards
    PagerDuty: &sentinel.PagerDutyConfig{
        IntegrationKey: os.Getenv("PD_ROUTING_KEY"),
        MinCVSS:        9.0, // pages only on critical
    },
},`}
      />

      <h2>6. SSRF-hardened HTTP client</h2>
      <p>
        Webhook delivery, "fetch from URL" features, OEmbed expansion, link previews — anywhere
        the server makes an outbound request triggered by user input is an SSRF surface. Use
        <code>sentinel.HTTPClient()</code> as a drop-in <code>*http.Client</code>. Default
        denylist covers loopback, private ranges, AWS IMDS, GCP metadata, and DNS rebinding.
      </p>
      <CodeBlock
        language="go"
        code={`client := sentinel.HTTPClient(sentinel.HTTPClientOptions{
    Reporter: pipe, // SSRF attempts show up in the dashboard
})
resp, err := client.Get(userSuppliedURL) // safely`}
      />

      <h2>7. CSP violation receiver</h2>
      <p>
        Browsers can now POST CSP violation reports to <code>POST /sentinel/csp-report</code>.
        Both the legacy and Reports API JSON shapes are accepted. Violations flow through the
        same pipeline as WAF events so they show up in the dashboard threats feed.
      </p>
      <CodeBlock
        language="go"
        code={`r.Use(middleware.CSPMiddleware(middleware.CSPConfig{
    Enabled:    true,
    Mode:       middleware.CSPReportOnly,
    Directives: "default-src 'self'; script-src 'self' 'nonce-XYZ'",
    ReportURI:  "/sentinel/csp-report",
}))`}
      />

      <h2>8. CAPTCHA tier on AuthShield</h2>
      <p>
        The middle ground between "fine" and "locked out". When an IP crosses
        <code>CAPTCHAThreshold</code> failed logins, the next attempt requires a valid CAPTCHA
        token. Plug in hCaptcha, Cloudflare Turnstile, Google reCAPTCHA v2, or the self-hosted
        arithmetic challenge for no-third-party setups.
      </p>
      <CodeBlock
        language="go"
        code={`CAPTCHA: sentinel.CAPTCHAConfig{
    TurnstileSecret: os.Getenv("TURNSTILE_SECRET"),
},
AuthShield: sentinel.AuthShieldConfig{
    Enabled:           true,
    MaxFailedAttempts: 5,
    CAPTCHAThreshold:  3, // CAPTCHA from attempt #3, lock at #5
},`}
      />

      <h2>9. Real Postgres adapter</h2>
      <p>
        Previously a stub that silently fell through to in-memory storage when
        <code>Driver: sentinel.Postgres</code> was selected. v2 wires a proper Postgres backend
        through GORM with the same models the SQLite adapter uses.
      </p>

      <h2>10. AI daily call cap</h2>
      <p>
        <code>AIConfig.MaxCallsPerDay</code> (default 500) caps the total upstream LLM call
        budget per UTC day so a runaway natural-language-query loop or misbehaving cron can't
        burn the monthly bill in an afternoon. The cache is applied inside the budget so
        cached hits don't burn quota.
      </p>

      <h2>11. Pipeline drop visibility</h2>
      <p>
        <code>GET /sentinel/api/performance/overview</code> now returns
        <code>pipeline_dropped</code> and <code>pipeline_emitted</code>. Drops happen exactly
        when an attack is overwhelming the buffer — alert on this.
      </p>

      <h2>12. GORM plugin auto-wired</h2>
      <p>
        Pass a non-nil <code>*gorm.DB</code> to <code>Mount</code> / <code>MountE</code> and the
        audit + query-shield plugin is registered automatically. No second-step
        <code>db.Use(...)</code> call required.
      </p>

      <h2>Migration checklist</h2>
      <ol>
        <li>Set <code>Dashboard.Password</code> + <code>Dashboard.SecretKey</code> via env vars.</li>
        <li>Add your load balancer's CIDR to <code>WAFConfig.TrustedProxies</code>.</li>
        <li>If you call <code>WAFMiddleware</code> directly, pass <code>nil</code> as the new fourth argument when you have no custom rule engine.</li>
        <li>Decide if you want PagerDuty / CAPTCHA / SSRF guard / CSP receiver — all are additive opt-ins.</li>
        <li>If you were registering the GORM plugin manually, you can drop that call — pass the <code>*gorm.DB</code> to <code>Mount</code>.</li>
      </ol>
    </>
  );
}
