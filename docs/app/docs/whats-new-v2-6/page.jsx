import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';

export const metadata = {
  title: "What's New in v2.6 - Sentinel Docs",
  description:
    'Sentinel v2.6 release notes: dashboard settings that survive a restart and reach every replica, an allowlist for your own redirect hosts, and whitelisted IPs that are no longer forgotten.',
  alternates: {
    canonical: 'https://sentinel-go-sdk.vercel.app/docs/whats-new-v2-6',
  },
  openGraph: {
    title: "What's New in v2.6 - Sentinel Docs",
    description:
      'Dashboard settings outlive the process and reach every replica; your own callbacks stop being reported as open redirects.',
    url: 'https://sentinel-go-sdk.vercel.app/docs/whats-new-v2-6',
    type: 'article',
  },
};

export default function WhatsNewV26() {
  return (
    <>
      <h1>What&apos;s New in v2.6</h1>
      <p>
        v2.5 made rate limits and lockouts hold across replicas. v2.6 does the same for the settings
        you change from the dashboard, and gives the open-redirect rule a way to tell your hosts
        from someone else&apos;s. Full details are in{' '}
        <a href="https://github.com/MUKE-coder/sentinel/blob/main/CHANGELOG.md">CHANGELOG.md</a>.
      </p>

      <h2 id="settings">Dashboard settings outlive the process</h2>
      <p>Four things can be changed from the dashboard rather than in code:</p>
      <ul>
        <li>the WAF&apos;s mode and per-category sensitivity</li>
        <li>its custom rules</li>
        <li>the per-route rate limits</li>
        <li>the alert threshold</li>
      </ul>
      <p>
        Until v2.6 each change applied to the single instance that served the request. It was lost
        on the next restart, and behind a load balancer the dashboard showed one value while the
        other replicas went on enforcing another — switching the WAF to block mode during an
        incident quietly protected one instance out of three.
      </p>
      <p>
        Those settings are now stored as a snapshot and applied by every replica. There is nothing
        to configure: any storage backend that can keep them does, and the SQLite, Postgres, and
        in-memory stores all can. Each replica picks up a change within{' '}
        <code>Storage.SyncInterval</code>, and a replica that scales up starts from the same
        settings as the rest.
      </p>
      <CodeBlock
        language="go"
        code={`sentinel.Mount(r, nil, sentinel.Config{
    Storage: sentinel.StorageConfig{
        Driver: sentinel.Postgres,
        DSN:    os.Getenv("DATABASE_URL"),

        // How soon a change made on another replica applies here.
        // Default 5s; a negative value turns polling off.
        SyncInterval: 5 * time.Second,
    },
})`}
      />
      <Callout type="warning" title="Stored settings win over your config">
        <p>
          Once something is changed from the dashboard, that value keeps applying — including after
          a deploy that sets a different value in code. This is deliberate: a change made during an
          incident shouldn&apos;t be undone by the next release.
        </p>
        <p>
          To hand control back to your <code>Config</code>, discard the stored settings. Every
          replica picks that up on its next poll.
        </p>
      </Callout>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# What is stored, and what your config asked for
curl http://localhost:8080/sentinel/api/settings/live \\
  -H "Authorization: Bearer $TOKEN"

# Discard the stored settings everywhere
curl -X DELETE http://localhost:8080/sentinel/api/settings/live \\
  -H "Authorization: Bearer $TOKEN"`}
      />
      <p>
        Every change is audited with the user and the old and new values. If your storage backend
        cannot keep settings, the change still applies to the instance you are talking to and the
        response carries a <code>warning</code> saying so, instead of looking permanent.
      </p>

      <h2 id="redirect-hosts">Your own callbacks are not open redirects</h2>
      <p>
        <code>callback=https://app.example.com/oauth</code> is the shape of an open redirect and the
        shape of an ordinary OAuth callback. Sentinel has no way to know which hostnames are yours,
        so it reported both — two of the nine false positives in the{' '}
        <a href="/docs/waf#accuracy">detection corpus</a> are exactly this. Tell it which hosts you
        own:
      </p>
      <CodeBlock
        language="go"
        code={`WAF: sentinel.WAFConfig{
    Enabled: true,
    Mode:    sentinel.ModeBlock,
    AllowedRedirectHosts: []string{
        "example.com",        // exact host, port ignored
        "*.apps.example.com", // any subdomain, not the bare domain
    },
},`}
      />
      <p>
        A redirect to one of those passes. A redirect anywhere else is still reported, and so is a
        request carrying even one outside target alongside yours — or a target Sentinel cannot
        parse, because a redirect it cannot read is not one it should vouch for. Encoded targets are
        decoded first, double-encoded ones included. <code>ValidateConfig</code> rejects entries
        written as URLs and warns when the list is set while the rule is off.
      </p>

      <h2 id="fixes">Fixes</h2>
      <ul>
        <li>
          <strong>Whitelisted IPs were forgotten on restart</strong> and never shared between
          replicas. They were written to storage, but only ever held in the memory of the process
          that added them, so after a restart every whitelisted IP silently went back to being
          inspected. The cache is now rebuilt from storage.
        </li>
        <li>
          <strong>A block made on one replica took up to 30 seconds to apply on the others.</strong>{' '}
          It is 5 seconds now, and configurable. The replica making the block still applies it
          immediately.
        </li>
        <li>
          <strong>One Redis call per rate-limited request instead of two.</strong> Publishing{' '}
          <code>X-RateLimit-Remaining</code> meant asking for the decision and then for the usage; a
          store can now answer both at once.
        </li>
        <li>
          <strong>The dashboard&apos;s first load is about 240 KB instead of 720 KB.</strong> Pages
          are loaded on demand, and only the two pages with charts download the charting library.
        </li>
      </ul>

      <h2 id="upgrade">Upgrading</h2>
      <p>Nothing is required. Two things are worth knowing:</p>
      <ul>
        <li>
          The first time someone changes a setting from the dashboard, it becomes sticky — including
          across deploys. <code>DELETE /sentinel/api/settings/live</code> returns control to your{' '}
          <code>Config</code>.
        </li>
        <li>
          Each replica now polls storage every 5 seconds for blocks, whitelist entries, and
          settings. Set <code>Storage.SyncInterval</code> to tune it, or to a negative value to turn
          polling off.
        </li>
      </ul>
    </>
  );
}
