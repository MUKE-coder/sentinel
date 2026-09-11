import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';

export const metadata = {
  title: "What's New in v2.5 - Sentinel Docs",
  description:
    'Sentinel v2.5 release notes: rate limits and AuthShield lockouts that hold across replicas, with a Redis counter store.',
  alternates: {
    canonical: 'https://sentinel-go-sdk.vercel.app/docs/whats-new-v2-5',
  },
  openGraph: {
    title: "What's New in v2.5 - Sentinel Docs",
    description: 'Rate limits and lockouts that hold across replicas, backed by Redis.',
    url: 'https://sentinel-go-sdk.vercel.app/docs/whats-new-v2-5',
    type: 'article',
  },
};

export default function WhatsNewV25() {
  return (
    <>
      <h1>What&apos;s New in v2.5</h1>
      <p>
        v2.5.0 makes rate limits and AuthShield lockouts hold when your application runs as more
        than one instance. Full details are in{' '}
        <a href="https://github.com/MUKE-coder/sentinel/blob/main/CHANGELOG.md">CHANGELOG.md</a>.
      </p>

      <h2 id="shared-counters">Limits that hold across replicas</h2>
      <p>
        Before v2.5, rate-limit counters and AuthShield&apos;s failed-login counts lived in each
        process. Behind a load balancer with N instances, a client got N times every limit, and N
        times the failed logins before a lockout. <code>Config.Counters</code> now takes a shared
        store:
      </p>
      <CodeBlock
        language="go"
        code={`import (
    "github.com/MUKE-coder/sentinel/v2/redisstore"
    "github.com/redis/go-redis/v9"
)

client := redis.NewClient(&redis.Options{Addr: "redis:6379"})

sentinel.Mount(r, nil, sentinel.Config{
    Counters: redisstore.New(client),
    RateLimit: sentinel.RateLimitConfig{
        Enabled: true,
        ByIP:    &sentinel.Limit{Requests: 100, Window: time.Minute},
    },
    AuthShield: sentinel.AuthShieldConfig{Enabled: true, LoginRoute: "/api/login"},
})`}
      />
      <p>
        <code>redisstore</code> works with a single Redis server, Redis Sentinel, or a cluster. Each
        rate-limit decision runs as one Lua script, so two replicas can&apos;t both take the last
        slot. If several applications share one Redis, give each one its own{' '}
        <code>redisstore.WithPrefix</code>.
      </p>
      <Callout type="info" title="If Redis goes down">
        Requests are allowed rather than failed, and the error is logged at most once a minute. Set
        timeouts on the Redis client so a slow Redis can&apos;t hold requests up.
      </Callout>
      <p>
        Without <code>Counters</code>, nothing changes: counters stay in memory, as before.
        Scaling out also needs:
      </p>
      <ul>
        <li>shared storage (Postgres)</li>
        <li>
          the same <code>Dashboard.SecretKey</code> on every replica
        </li>
        <li>
          <code>WAF.TrustedProxies</code> set to your load balancer
        </li>
      </ul>
      <p>
        <code>examples/multi-replica</code> in the repository runs two replicas behind Caddy with all
        of that in place.
      </p>

      <h2 id="counter-store">Your own counter store</h2>
      <p>
        <code>sentinel.CounterStore</code> is an interface. To use something other than Redis,
        implement it and run the <code>countertest</code> conformance suite from your tests. The
        in-memory and Redis stores both pass it.
      </p>

      <h2 id="changes">Other changes</h2>
      <ul>
        <li>
          Credential-stuffing detection counts distinct usernames within{' '}
          <code>LockoutDuration</code>. Before, it counted every username an IP had tried since its
          last successful login.
        </li>
        <li>
          The dashboard&apos;s AuthShield panel lists only IPs with failures or a lockout in the
          current window.
        </li>
      </ul>
    </>
  );
}
