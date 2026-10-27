import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';

export const metadata = {
  title: "What's New in v2.8 - Sentinel Docs",
  description:
    'Sentinel v2.8 release notes: automatic blocking of addresses that keep attacking, a one-call sweep for repeat offenders already in your threat log, and detection for every env-file probe shape.',
  alternates: {
    canonical: 'https://sentinel-go-sdk.vercel.app/docs/whats-new-v2-8',
  },
  openGraph: {
    title: "What's New in v2.8 - Sentinel Docs",
    description:
      'Scanners get blocked instead of logged: auto-block on behaviour, a bulk sweep for the backlog, and every env-file probe detected.',
    url: 'https://sentinel-go-sdk.vercel.app/docs/whats-new-v2-8',
    type: 'article',
  },
};

export default function WhatsNewV28() {
  return (
    <>
      <h1>What&apos;s New in v2.8</h1>
      <p>
        This release came out of one deployment&apos;s threat log: 18,405 rows, nearly all of them
        scanners asking for env files from a handful of addresses. Every request detected, every
        request recorded, every request answered — and nothing stopped. Full details are in{' '}
        <a href="https://github.com/MUKE-coder/sentinel/blob/main/CHANGELOG.md">CHANGELOG.md</a>.
      </p>

      <h2 id="env-probes">Every env-file probe is detected</h2>
      <p>
        <code>/.env</code> and <code>/.env.production</code> were detected.{' '}
        <code>/sendgrid.env</code>, <code>/gemini.env</code> and <code>/laravel.env</code> were
        not: they stopped matching in v2.4.0, when the LFI pattern was tightened to clear a{' '}
        <code>report.env.pdf</code> false positive. Prefixed env files are most of what a scanner
        asks for.
      </p>
      <p>
        All three shapes match now, and the lookalikes still pass — a document called{' '}
        <code>report.env.pdf</code> is a PDF, <code>/sendgrid.env</code> is someone looking for
        your API keys. The{' '}
        <a href="/docs/waf#accuracy">detection corpus</a> carries the probe list from that log,
        with the false-positive count unchanged.
      </p>

      <h2 id="auto-block">An address that keeps attacking gets blocked</h2>
      <p>
        A scanner walking a list of paths trips detection thousands of times. Until now each of
        those requests was inspected, recorded and answered, one at a time, for hours.{' '}
        <code>AutoBlock</code> counts threats per address and blocks one that goes over the line:
      </p>
      <CodeBlock
        language="go"
        code={`AutoBlock: sentinel.AutoBlockConfig{
    Enabled:     true,
    Threats:     10,               // within Window
    Window:      10 * time.Minute,
    Duration:    24 * time.Hour,   // 0 blocks until someone lifts it
    MinSeverity: sentinel.SeverityHigh,
    ExemptIPs:   []string{"203.0.113.0/24"},
},`}
      />
      <ul>
        <li>
          <strong>Behaviour, not reputation.</strong> <code>IPReputation.AutoBlock</code> acts on
          what a third party already knows about an address; this acts on what the address has
          just done to your application, which is the only thing that catches a scanner nobody has
          reported yet.
        </li>
        <li>
          <strong>Counted across replicas.</strong> Counting runs through{' '}
          <code>Config.Counters</code>, so threats spread over instances add up to one total, and
          a block made anywhere is enforced everywhere.
        </li>
        <li>
          <strong>Hard to turn against you.</strong> <code>MinSeverity</code> (default High) keeps
          a stream of low-severity oddities from accumulating into a block, <code>ExemptIPs</code>{' '}
          and the whitelist are never blocked, and each threat counts once by its own ID. Every
          automatic block is written to the audit log like a manual one.
        </li>
      </ul>
      <Callout type="warning" title="It only sees what happens after you turn it on">
        <p>
          Auto-block counts threats as they arrive. The addresses already in your threat log are a
          separate job — that is what the sweep below is for.
        </p>
      </Callout>

      <h2 id="offenders">Blocking the backlog in one call</h2>
      <p>
        Going through a scan by hand is how a threat log with thousands of rows gets ignored
        instead of acted on. The IP Management page has a <strong>Block repeat offenders</strong>{' '}
        panel, and the same thing is an endpoint:
      </p>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Who would be blocked? Nothing is blocked by a dry run.
curl -X POST http://localhost:8080/sentinel/api/ip/block-offenders \\
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{"min_threats": 5, "since": "168h", "dry_run": true}'

# Block them, for 24 hours.
curl -X POST http://localhost:8080/sentinel/api/ip/block-offenders \\
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \\
  -d '{"min_threats": 5, "since": "168h", "duration": "24h"}'`}
      />
      <p>
        Whitelisted and already-blocked addresses are skipped, a run is capped at 1,000 addresses
        (<code>truncated</code> says when more remain), and the sweep is audited once with the
        addresses as evidence. The dashboard panel always previews before it blocks.
      </p>

      <h2 id="recipe">Stopping an env scan</h2>
      <p>If your threat log looks like the one above, this is the whole change:</p>
      <CodeBlock
        language="go"
        code={`sentinel.Mount(r, nil, sentinel.Config{
    // Refuse the probes rather than recording them. Run in ModeLog first
    // and read the Threats page if you have not already.
    WAF: sentinel.WAFConfig{Enabled: true, Mode: sentinel.ModeBlock},

    // And stop answering the address at all once it is clearly scanning.
    AutoBlock: sentinel.AutoBlockConfig{Enabled: true},
})`}
      />
      <p>
        Then clear the backlog once from the dashboard. New scanners are blocked about ten probes
        in, which for the log this came from is a few seconds rather than a few hours.
      </p>

      <h2 id="upgrade">Upgrading</h2>
      <p>
        Nothing is required and no defaults changed: <code>AutoBlock</code> is off until you turn
        it on. The only behaviour change is that prefixed env probes are detected again, so if you
        serve a file whose name ends in <code>.env</code> — unusual, but{' '}
        <code>/exports/data.env</code> would qualify — exclude that route with{' '}
        <code>WAF.ExcludeRoutes</code>.
      </p>
    </>
  );
}
