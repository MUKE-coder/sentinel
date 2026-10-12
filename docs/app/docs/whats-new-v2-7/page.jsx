import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';

export const metadata = {
  title: "What's New in v2.7 - Sentinel Docs",
  description:
    'Sentinel v2.7 release notes: a MySQL storage adapter, lockouts that no longer bar everyone sharing an address, an honest CAPTCHA tier, and a dashboard login budget that holds across replicas.',
  alternates: {
    canonical: 'https://sentinel-go-sdk.vercel.app/docs/whats-new-v2-7',
  },
  openGraph: {
    title: "What's New in v2.7 - Sentinel Docs",
    description:
      'MySQL storage, lockouts that spare everyone behind a shared address, and a CAPTCHA tier that actually fires.',
    url: 'https://sentinel-go-sdk.vercel.app/docs/whats-new-v2-7',
    type: 'article',
  },
};

export default function WhatsNewV27() {
  return (
    <>
      <h1>What&apos;s New in v2.7</h1>
      <p>
        Four reported issues, and three more bugs found while fixing them. Full details are in{' '}
        <a href="https://github.com/MUKE-coder/sentinel/blob/main/CHANGELOG.md">CHANGELOG.md</a>.
      </p>

      <h2 id="mysql">MySQL storage</h2>
      <p>
        <code>sentinel.MySQL</code> was exported but <code>Mount</code> had no case for it, so an
        application configured for MySQL fell through to <strong>in-memory storage</strong>: the
        dashboard looked healthy and every threat, block, and audit entry disappeared on restart.
        The same silent fallback hid a misspelled driver name.
      </p>
      <CodeBlock
        language="go"
        code={`sentinel.Mount(r, nil, sentinel.Config{
    Storage: sentinel.StorageConfig{
        Driver: sentinel.MySQL,
        // parseTime=True is required: without it the driver returns []byte
        // where Sentinel expects time.Time.
        DSN: "user:pass@tcp(127.0.0.1:3306)/sentinel?charset=utf8mb4&parseTime=True",
    },
})`}
      />
      <p>
        The adapter reuses the same GORM models as SQLite and Postgres, so the schema and feature
        set are identical. A driver <code>Mount</code> does not recognise is now a startup error
        rather than a quiet downgrade to memory.
      </p>
      <Callout type="info" title="Two things MySQL needed that the others didn't">
        <p>
          An untagged string column becomes <code>LONGTEXT</code> in MySQL, which cannot be
          indexed, so the adapter bounds them and the columns holding paths, user agents, and JSON
          blobs are explicitly <code>text</code>.
        </p>
        <p>
          The driver&apos;s default timestamp column is <code>datetime(3)</code>, which truncated
          the timestamps the audit log&apos;s hash chain covers — a chain written to MySQL failed
          its own verification, with every entry reading back as modified. The adapter asks for{' '}
          <code>datetime(6)</code>.
        </p>
      </Callout>

      <h2 id="lockouts">A lockout no longer bars everyone sharing an address</h2>
      <p>
        AuthShield counted failed sign-ins per client address and locked <em>that address</em>.
        Behind NAT or CGNAT an address is an office, a university, an apartment block, or a mobile
        carrier: five mistakes by one person barred everybody sharing that egress address for
        fifteen minutes. Worse, it needed no access to the target — failing sign-ins against any
        username from a victim&apos;s egress address locked whoever happened to share it.
      </p>
      <p>
        The default is now the (address, account) pair. The person who failed is stopped; their
        neighbours are not.
      </p>
      <CodeBlock
        language="go"
        code={`AuthShield: sentinel.AuthShieldConfig{
    Enabled:    true,
    LoginRoute: "/api/login",

    // "pair" (default) bars that account from that address.
    // "ip" is the pre-v2.7 behaviour; "account" bars it everywhere.
    LockoutKey: sentinel.LockoutPair,

    // Never locked by address, however you key lockouts: office NAT,
    // CGNAT, a VPN gateway.
    ExemptIPs: []string{"203.0.113.0/24"},
},`}
      />
      <p>
        A per-account lockout cannot see one machine working through many accounts, so an address
        that accumulates <code>AddressFailureBudget</code> failures (default{' '}
        <code>MaxFailedAttempts × 4</code>) has every attempt refused for{' '}
        <code>AddressCooldown</code> — one minute by default. Deliberately short, because an
        address may be thousands of people, and an attacker&apos;s throughput still collapses.
        Refusals now carry <code>Retry-After</code>, and the dashboard lists the accounts locked
        from each address. See{' '}
        <a href="/docs/auth-shield#what-a-lockout-bars">What a lockout bars</a>.
      </p>

      <h2 id="captcha">A CAPTCHA tier that actually fires</h2>
      <p>
        <code>CAPTCHAThreshold</code> was given a value whether or not a CAPTCHA provider existed,
        and validation only complained about <em>more than one</em> provider. So the default state
        of every deployment that enabled AuthShield without CAPTCHA was a tier between
        &quot;allow&quot; and &quot;locked out&quot; that could never fire and said nothing about
        it. Config that reads as a defence and does nothing is worse than no config.
      </p>
      <p>
        The threshold now defaults to 0 unless a provider is configured, and{' '}
        <code>ValidateConfig</code> warns when one is set without a provider. This matters more
        than it used to: with lockouts keyed on the pair, the CAPTCHA tier is the escalation path
        for a suspicious shared address.
      </p>

      <h2 id="login-budget">The dashboard login budget holds across replicas</h2>
      <p>
        v2.5 moved rate limits and AuthShield onto a shared counter store, but the dashboard&apos;s
        own limiter — ten login attempts per address per quarter hour — stayed in process memory.
        Four replicas therefore gave an attacker forty guesses at the dashboard password. It now
        uses the same <code>Config.Counters</code> store, and fails open on a store outage rather
        than locking everyone out of the dashboard.
      </p>

      <h2 id="other-fixes">Found while fixing those</h2>
      <ul>
        <li>
          <strong>Replicas starting together failed their migrations.</strong> They all run{' '}
          <code>AutoMigrate</code> against the one shared database, and the losers of that race
          died with &quot;table already exists&quot; — three of four replicas in a test. Migrations
          are retried once. Postgres had the same exposure.
        </li>
        <li>
          <strong><code>WAF.ExcludeIPs</code> honours CIDR ranges.</strong> Documented as &quot;IP
          addresses or CIDR ranges&quot; since v2.0, but entries were compared as exact strings: a{' '}
          <code>10.0.0.0/8</code> entry exempted exactly one client — the one whose address was
          that literal string.
        </li>
        <li>
          <strong>An empty Postgres or MySQL DSN is reported.</strong>{' '}
          <code>ApplyDefaults</code> used to hand every driver the SQLite filename, so a config
          with no DSN looked complete and failed later at connect time.
        </li>
      </ul>

      <h2 id="upgrade">Upgrading</h2>
      <p>Nothing is required, but three defaults changed:</p>
      <div className="overflow-x-auto">
        <table>
          <thead>
            <tr>
              <th>Change</th>
              <th>If you want the old behaviour</th>
            </tr>
          </thead>
          <tbody>
            <tr>
              <td>A lockout bars the (address, account) pair, not the address</td>
              <td>
                <code>AuthShield.LockoutKey: sentinel.LockoutIP</code> — ideally with{' '}
                <code>ExemptIPs</code> for your shared egress ranges
              </td>
            </tr>
            <tr>
              <td>
                <code>CAPTCHAThreshold</code> defaults to 0 without a provider
              </td>
              <td>Configure a provider secret, or set the threshold explicitly</td>
            </tr>
            <tr>
              <td>An unrecognised <code>Storage.Driver</code> fails the mount</td>
              <td>
                Nothing — this one was hiding data loss. Check the driver name if a mount starts
                failing.
              </td>
            </tr>
          </tbody>
        </table>
      </div>
      <p>
        If your login handler does not report an account name (credentials in a header, or a field
        name of your own), add it to <code>AuthShield.UsernameFields</code> or set{' '}
        <code>sentinel_username</code> in the handler. Without one, a pair lockout has nothing to
        key on and the address is locked instead — what every application got before v2.7.
      </p>
    </>
  );
}
