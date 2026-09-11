import Callout from '@/components/Callout';

export const metadata = {
  title: "What's New in v2.4 - Sentinel Docs",
  description:
    'Sentinel v2.4 release notes: measured WAF accuracy and a double-encoding fix, no published dashboard secret, AI redaction, a tamper-evident audit log, and live IP reputation.',
  alternates: {
    canonical: 'https://sentinel-go-sdk.vercel.app/docs/whats-new-v2-4',
  },
  openGraph: {
    title: "What's New in v2.4 - Sentinel Docs",
    description:
      'Measured WAF accuracy, security fixes, AI redaction, a tamper-evident audit log, live IP reputation, and an upgrade checklist.',
    url: 'https://sentinel-go-sdk.vercel.app/docs/whats-new-v2-4',
    type: 'article',
  },
};

export default function WhatsNewV24() {
  return (
    <>
      <h1>What&apos;s New in v2.4</h1>
      <p>
        v2.4.0 is about evidence. The WAF&apos;s accuracy is now measured, and CI pins it.
        Defaults that relied on a secret published in the source are gone. Personal data stays out
        of AI prompts. The audit log can prove it hasn&apos;t been edited. Full details are in{' '}
        <a href="https://github.com/MUKE-coder/sentinel/blob/main/CHANGELOG.md">CHANGELOG.md</a>.
      </p>

      <Callout type="warning" title="Read before upgrading to v2.4.0">
        <ul>
          <li>
            Dashboard sessions end on restart unless <code>Dashboard.SecretKey</code> is set.
          </li>
          <li>The default password works only from localhost.</li>
          <li>AI features see redacted data.</li>
        </ul>
        <p>
          See the <a href="#upgrade">upgrade checklist</a>.
        </p>
      </Callout>

      <h2 id="security">Security fixes</h2>
      <ul>
        <li>
          <strong>Double encoding bypassed the WAF.</strong> The classifier decoded query values
          once, so <code>%2527</code> reached an app that decodes again as an apostrophe. Leftover
          percent-encoding in the path, parameter names and values, and bodies is now decoded up to
          two more times, and every layer is scanned. Form-encoded bodies are decoded too.
        </li>
        <li>
          <strong>No published JWT secret.</strong> An unset <code>Dashboard.SecretKey</code> used a
          value from the source code, so anyone could forge an admin token outside release mode. It
          now defaults to a random secret generated at each start.
        </li>
        <li>
          <strong>The default password works from localhost only.</strong> This means a direct
          loopback connection with no forwarding headers. <code>AllowInsecureDefaults</code> opts
          back in.
        </li>
        <li>
          <strong>Same-origin WebSocket.</strong> The live threat stream accepted browser handshakes
          from any origin.
        </li>
        <li>
          <strong>IP blocks work with the WAF disabled.</strong> They used to be enforced only inside
          the WAF middleware.
        </li>
      </ul>

      <h2 id="accuracy">Measured WAF accuracy</h2>
      <p>
        Two corpora in the repository, 89 legitimate-but-suspicious requests and 56 attacks, measure
        the built-in patterns at every sensitivity level. CI fails if a change adds false positives
        or misses. With the default rule set:
      </p>
      <ul>
        <li>9 of 89 false positives (10%), down from 32 of 84 (38%)</li>
        <li>56 of 56 attacks detected, up from 47 of 51</li>
      </ul>
      <p>
        See <a href="/docs/waf#accuracy">Measured Accuracy</a>. An attack regression suite also runs
        end to end:
      </p>
      <ul>
        <li>encoded payloads are blocked</li>
        <li>spoofed forwarding headers don&apos;t reset a rate limit or get out of an IP block</li>
        <li>credential stuffing still gets locked out</li>
      </ul>
      <p>
        <code>security/scan</code> runs ZAP and sqlmap against a deliberately injectable app.
      </p>

      <h2 id="ai-redaction">AI redaction, on by default</h2>
      <p>
        Before anything is sent to the AI provider:
      </p>
      <ul>
        <li>query values are masked and request bodies are dropped</li>
        <li>IPs are truncated (the last IPv4 octet; IPv6 down to its /48)</li>
        <li>emails, tokens, card numbers, and secrets are scrubbed</li>
      </ul>
      <p>
        The matched attack fragments are kept, so analyses still see what triggered a detection.{' '}
        <code>AI.Redaction</code> opts back out, field by field. See{' '}
        <a href="/docs/ai-analysis">AI Analysis</a>.
      </p>

      <h2 id="audit-chain">Tamper-evident audit log</h2>
      <p>
        Every audit entry is linked into a hash chain as it is stored.{' '}
        <code>GET /api/audit-logs/verify</code> reports:
      </p>
      <ul>
        <li>modified entries</li>
        <li>deletions</li>
        <li>broken links</li>
      </ul>
      <p>
        The dashboard&apos;s Audit page runs the same check through its <strong>Verify integrity</strong>{' '}
        button. Set <code>Storage.AuditKey</code> for an HMAC chain that someone with database access
        can&apos;t recompute. See <a href="/docs/audit-logging">Audit Logging</a>.
      </p>

      <h2 id="reputation">Live IP reputation and blocklist feeds</h2>
      <p>
        Attacking IPs are checked against AbuseIPDB as threats arrive, within a daily quota, and{' '}
        <code>AutoBlock</code> finally acts on them. <code>IPReputation.Feeds</code> downloads
        blocklists such as Spamhaus DROP and blocks their ranges. Feeds work without an API key.
        See <a href="/docs/threat-intelligence">Threat Intelligence</a>.
      </p>

      <h2 id="dashboard">Dashboard</h2>
      <ul>
        <li>The WAF page changes the mode and each category&apos;s sensitivity on the running WAF.</li>
        <li>IP blocks take a lifetime, from 1 hour to 30 days, or can be permanent.</li>
        <li>The Audit page verifies the hash chain.</li>
      </ul>

      <h2 id="upgrade">Upgrade checklist</h2>
      <ol>
        <li>
          Set <code>Dashboard.SecretKey</code> to at least 32 random bytes. Otherwise sessions end
          on every restart, and tokens don&apos;t work across replicas.
        </li>
        <li>
          If you reach the dashboard through Docker, a tunnel, or a reverse proxy, set{' '}
          <code>Dashboard.Password</code>. The default password is refused there.
        </li>
        <li>
          Set <code>Storage.AuditKey</code> so the audit chain is keyed.
        </li>
        <li>
          If you need raw payloads in AI analyses, set <code>AI.Redaction.SendPayloads</code>.
        </li>
        <li>
          Patterns changed. Run the WAF in log mode for a while and review the Threats page before
          going back to block mode. OpenRedirect now fires only on parameters named for a redirect.
        </li>
        <li>
          Add <code>IPReputation.Feeds</code> (for example, Spamhaus DROP) to block known-bad
          networks for free.
        </li>
      </ol>
    </>
  );
}
