import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';
import { FAQSchema, TechArticleSchema, SpeakableSchema } from '@/components/JsonLd';

export const metadata = {
  title: 'Rate Limiting - Sentinel Docs',
  description:
    'Set up multi-dimensional rate limiting in Sentinel with per-IP, per-user, per-route, and global limits using sliding window counters.',
  alternates: {
    canonical: 'https://sentinel-go-sdk.vercel.app/docs/rate-limiting',
  },
  openGraph: {
    title: 'Rate Limiting - Sentinel Docs',
    description:
      'Set up multi-dimensional rate limiting in Sentinel with per-IP, per-user, per-route, and global limits using sliding window counters.',
    url: 'https://sentinel-go-sdk.vercel.app/docs/rate-limiting',
    type: 'article',
  },
};

export default function RateLimiting() {
  return (
    <>
      <FAQSchema
        questions={[
          {
            q: 'What rate limit types does Sentinel support?',
            a: 'Sentinel supports four independent rate limit dimensions: per-IP (each client IP gets its own counter), per-user (requires a UserIDExtractor function), per-route (different limits for specific endpoints), and global (a single counter shared across all requests).',
          },
          {
            q: 'How do sliding window counters work in Sentinel?',
            a: 'The default sliding window counts requests over the window ending now: the previous window\'s count, weighted by how much of it still overlaps, plus the current window\'s count. That stops twice the limit from passing in a moment either side of a window boundary. Fixed window and token bucket are also available via RateLimitConfig.Strategy. A background goroutine removes idle counters every 30 seconds.',
          },
          {
            q: 'How do I set per-route rate limits in Sentinel?',
            a: 'Use the ByRoute field with a map of route paths to Limit structs. Keys are exact paths like /api/login or wildcard patterns like /v1/* and /api/apps/*/products; all paths matching one pattern share its counter. Route limits are tracked per IP, so each client gets its own counter per route.',
          },
          {
            q: 'What happens when a client is rate limited?',
            a: 'When a limit is exceeded, Sentinel returns HTTP 429 Too Many Requests with a JSON body containing an error code. Response headers include X-RateLimit-Limit, X-RateLimit-Remaining, and Retry-After so clients can self-regulate their request rate.',
          },
        ]}
      />
      <TechArticleSchema
        title="Sentinel Rate Limiting"
        description="Set up multi-dimensional rate limiting in Sentinel with per-IP, per-user, per-route, and global limits using sliding window counters."
        url="https://sentinel-go-sdk.vercel.app/docs/rate-limiting"
      />
      <SpeakableSchema
        url="https://sentinel-go-sdk.vercel.app/docs/rate-limiting"
        cssSelector={['.prose h1', '.prose h2', '.prose p']}
      />
      <h1>Rate Limiting</h1>
      <p>
        Sentinel provides multi-dimensional rate limiting with sliding window counters. You can
        enforce limits per IP address, per authenticated user, per route, and globally — all at the
        same time. Every dimension is evaluated independently, and a request must pass all applicable
        limits to be allowed through.
      </p>

      <Callout type="info" title="Opt-In Feature">
        Rate limiting is disabled by default. Set <code>Enabled: true</code> in your{' '}
        <code>RateLimitConfig</code> to activate it. You only need to configure the dimensions you
        care about — any dimension left as <code>nil</code> is simply skipped.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  ENABLING RATE LIMITING                                             */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="enabling">Enabling Rate Limiting</h2>
      <p>
        The simplest way to get started is to enable rate limiting with a single per-IP limit. This
        protects every route in your application from individual clients sending too many requests.
      </p>
      <CodeBlock
        language="go"
        filename="main.go"
        code={`import (
    "time"

    sentinel "github.com/MUKE-coder/sentinel/v2"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

    sentinel.Mount(r, nil, sentinel.Config{
        RateLimit: sentinel.RateLimitConfig{
            Enabled: true,
            ByIP:    &sentinel.Limit{Requests: 100, Window: time.Minute},
        },
    })

    r.GET("/api/hello", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "Hello, World!"})
    })

    r.Run(":8080")
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  RATE LIMIT DIMENSIONS                                              */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="dimensions">Rate Limit Dimensions</h2>
      <p>
        Sentinel supports four independent rate limit dimensions. You can use any combination of
        them. Each dimension maintains its own set of counters and is evaluated in a specific order.
      </p>

      <h3>The Limit Struct</h3>
      <p>
        Every dimension is configured with the same <code>Limit</code> struct, which defines a
        maximum number of requests within a time window.
      </p>
      <CodeBlock
        language="go"
        showLineNumbers={false}
        code={`type Limit struct {
    Requests int           // Maximum requests allowed within the window
    Window   time.Duration // Time window (e.g., time.Minute, 15 * time.Minute)
}`}
      />

      <h3>Per-IP (<code>ByIP</code>)</h3>
      <p>
        Each unique client IP address gets its own counter. This is the most common dimension and
        protects against individual clients overwhelming your server.
      </p>
      <CodeBlock
        language="go"
        showLineNumbers={false}
        code={`// 100 requests per minute per IP address
ByIP: &sentinel.Limit{Requests: 100, Window: time.Minute}`}
      />

      <h3>Per-User (<code>ByUser</code>)</h3>
      <p>
        Each authenticated user gets their own counter, identified by a user ID string. This
        requires a <code>UserIDExtractor</code> function that extracts the user ID from the
        request. If the extractor returns an empty string (unauthenticated request), the per-user
        limit is skipped for that request.
      </p>
      <CodeBlock
        language="go"
        showLineNumbers={false}
        code={`// 500 requests per minute per authenticated user
ByUser: &sentinel.Limit{Requests: 500, Window: time.Minute},

// Tell Sentinel how to identify the user
UserIDExtractor: func(c *gin.Context) string {
    return c.GetHeader("X-User-ID")
},`}
      />

      <Callout type="warning" title="UserIDExtractor Required">
        The <code>ByUser</code> limit is only enforced when <code>UserIDExtractor</code> is set.
        Without it, per-user rate limiting is silently skipped even if <code>ByUser</code> is
        configured.
      </Callout>

      <h3>Per-Route (<code>ByRoute</code>)</h3>
      <p>
        Different routes can have different limits. The <code>ByRoute</code> map keys are exact
        route paths. Each route limit is tracked per IP address (the counter key is a combination
        of the route path and the client IP).
      </p>
      <CodeBlock
        language="go"
        showLineNumbers={false}
        code={`// Strict limits on sensitive endpoints
ByRoute: map[string]sentinel.Limit{
    "/api/login":          {Requests: 5, Window: 15 * time.Minute},
    "/api/register":       {Requests: 3, Window: time.Hour},
    "/api/password-reset": {Requests: 3, Window: time.Hour},
},`}
      />

      <h3>Global</h3>
      <p>
        A single counter shared across all requests regardless of source. This is a safety net to
        protect your application from being overwhelmed by aggregate traffic.
      </p>
      <CodeBlock
        language="go"
        showLineNumbers={false}
        code={`// 5000 total requests per minute across all clients
Global: &sentinel.Limit{Requests: 5000, Window: time.Minute}`}
      />

      <h3>All Dimensions Together</h3>
      <CodeBlock
        language="go"
        filename="config.go"
        code={`RateLimit: sentinel.RateLimitConfig{
    Enabled:  true,
    Strategy: sentinel.SlidingWindow,

    // Per-IP: 100 req/min
    ByIP: &sentinel.Limit{Requests: 100, Window: time.Minute},

    // Per-user: 500 req/min (requires UserIDExtractor)
    ByUser: &sentinel.Limit{Requests: 500, Window: time.Minute},

    // Per-route: different limits for sensitive endpoints
    ByRoute: map[string]sentinel.Limit{
        "/api/login":    {Requests: 5, Window: 15 * time.Minute},
        "/api/register": {Requests: 3, Window: time.Hour},
    },

    // Global: 5000 req/min total
    Global: &sentinel.Limit{Requests: 5000, Window: time.Minute},

    // Extract user ID for per-user limiting
    UserIDExtractor: func(c *gin.Context) string {
        return c.GetHeader("X-User-ID")
    },
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  CONFIGURATION REFERENCE TABLE                                      */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="config-reference">Configuration Reference</h2>
      <table>
        <thead>
          <tr>
            <th>Field</th>
            <th>Type</th>
            <th>Default</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>Enabled</code></td>
            <td><code>bool</code></td>
            <td><code>false</code></td>
            <td>Enables the rate limiting middleware.</td>
          </tr>
          <tr>
            <td><code>Strategy</code></td>
            <td><code>RateLimitStrategy</code></td>
            <td><code>sentinel.SlidingWindow</code></td>
            <td>Algorithm used for counting. Options: <code>sentinel.SlidingWindow</code>, <code>sentinel.FixedWindow</code>, <code>sentinel.TokenBucket</code>.</td>
          </tr>
          <tr>
            <td><code>ByIP</code></td>
            <td><code>*Limit</code></td>
            <td><code>nil</code></td>
            <td>Per-IP rate limit. Each unique client IP gets its own counter.</td>
          </tr>
          <tr>
            <td><code>ByUser</code></td>
            <td><code>*Limit</code></td>
            <td><code>nil</code></td>
            <td>Per-user rate limit. Requires a <code>UserIDExtractor</code>.</td>
          </tr>
          <tr>
            <td><code>ByRoute</code></td>
            <td><code>map[string]Limit</code></td>
            <td><code>nil</code></td>
            <td>Per-route rate limits. Keys are exact route paths.</td>
          </tr>
          <tr>
            <td><code>Global</code></td>
            <td><code>*Limit</code></td>
            <td><code>nil</code></td>
            <td>Global rate limit applied across all requests regardless of source.</td>
          </tr>
          <tr>
            <td><code>UserIDExtractor</code></td>
            <td><code>func(*gin.Context) string</code></td>
            <td><code>nil</code></td>
            <td>Function to extract a user ID from the request for per-user limiting.</td>
          </tr>
        </tbody>
      </table>

      {/* ------------------------------------------------------------------ */}
      {/*  PRIORITY ORDER                                                     */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="priority-order">Priority Order</h2>
      <p>
        When multiple dimensions are configured, Sentinel evaluates them in a specific order. The
        request is rejected as soon as any dimension's limit is exceeded — remaining dimensions are
        not checked.
      </p>
      <table>
        <thead>
          <tr>
            <th>Priority</th>
            <th>Dimension</th>
            <th>Counter Key</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>1 (highest)</strong></td>
            <td>Per-Route</td>
            <td><code>route:/path:IP</code></td>
            <td>Checked first. Only applies if the request path matches a key in <code>ByRoute</code>.</td>
          </tr>
          <tr>
            <td><strong>2</strong></td>
            <td>Per-IP</td>
            <td><code>ip:IP</code></td>
            <td>Checked second. Applies to every request when <code>ByIP</code> is set.</td>
          </tr>
          <tr>
            <td><strong>3</strong></td>
            <td>Per-User</td>
            <td><code>user:userID</code></td>
            <td>Checked third. Only applies when <code>ByUser</code> is set and <code>UserIDExtractor</code> returns a non-empty string.</td>
          </tr>
          <tr>
            <td><strong>4 (lowest)</strong></td>
            <td>Global</td>
            <td><code>global</code></td>
            <td>Checked last. A single counter shared across all requests.</td>
          </tr>
        </tbody>
      </table>

      <Callout type="info" title="Independent Evaluation">
        Route limits do not replace IP or user limits — they are additive. A request to{' '}
        <code>/api/login</code> is checked against the route limit <strong>and</strong> the IP
        limit <strong>and</strong> the user limit <strong>and</strong> the global limit (if all are
        configured). The request must pass every applicable check.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  RESPONSE HEADERS                                                   */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="response-headers">Response Headers</h2>
      <p>
        Sentinel automatically sets standard rate limit headers on responses so clients can
        self-regulate. When a limit is exceeded, the client receives a{' '}
        <code>429 Too Many Requests</code> response with a JSON body.
      </p>

      <table>
        <thead>
          <tr>
            <th>Header</th>
            <th>Description</th>
            <th>Example</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>X-RateLimit-Limit</code></td>
            <td>The maximum number of requests allowed in the current window.</td>
            <td><code>100</code></td>
          </tr>
          <tr>
            <td><code>X-RateLimit-Remaining</code></td>
            <td>The number of requests remaining in the current window.</td>
            <td><code>73</code></td>
          </tr>
          <tr>
            <td><code>Retry-After</code></td>
            <td>Seconds until the rate limit window resets. Only sent when the limit is exceeded (429 response).</td>
            <td><code>60</code></td>
          </tr>
        </tbody>
      </table>

      <p>
        On a successful request, the response includes <code>X-RateLimit-Limit</code> and{' '}
        <code>X-RateLimit-Remaining</code> based on the per-IP limit. When a limit is exceeded, the
        response body is:
      </p>
      <CodeBlock
        language="json"
        showLineNumbers={false}
        code={`{
    "error": "Rate limit exceeded",
    "code": "RATE_LIMITED"
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  PER-ROUTE LIMITS                                                   */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="per-route-limits">Per-Route Limits</h2>
      <p>
        Per-route limits let you apply different thresholds to different endpoints. This is
        especially useful for protecting sensitive routes like login, registration, and password
        reset endpoints with much stricter limits than the rest of your API.
      </p>
      <CodeBlock
        language="go"
        filename="main.go"
        code={`sentinel.Mount(r, nil, sentinel.Config{
    RateLimit: sentinel.RateLimitConfig{
        Enabled: true,

        // General API limit: 100 req/min per IP
        ByIP: &sentinel.Limit{Requests: 100, Window: time.Minute},

        // Strict limits on sensitive routes
        ByRoute: map[string]sentinel.Limit{
            // Login: 5 attempts per 15 minutes per IP
            "/api/login": {Requests: 5, Window: 15 * time.Minute},

            // Registration: 3 per hour per IP
            "/api/register": {Requests: 3, Window: time.Hour},

            // Password reset: 3 per hour per IP
            "/api/password-reset": {Requests: 3, Window: time.Hour},

            // File upload: 10 per minute per IP
            "/api/upload": {Requests: 10, Window: time.Minute},
        },
    },
})`}
      />
      <p>
        Route limits are keyed by the combination of the route path and the client IP. For example,
        a request to <code>/api/login</code> from IP <code>1.2.3.4</code> uses the counter key{' '}
        <code>route:/api/login:1.2.3.4</code>. This means each IP gets its own counter for each
        route-limited path.
      </p>

      <Callout type="info" title="Exact Paths and Wildcard Patterns">
        A plain key matches exactly: <code>/api/login</code> does not match <code>/api/login/</code>{' '}
        (query strings are ignored). Keys can also be patterns — <code>/v1/*</code> or{' '}
        <code>/v1/**</code> for a whole subtree, <code>/api/apps/*/products</code> for one segment,
        or <code>/api/apps/*/products/**</code> for both. Every path matching a pattern shares that
        pattern's counter, so rotating sub-paths can't reset a client's budget. When an exact key and
        a pattern both match, the exact key wins; otherwise the longest pattern does.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  HOW IT WORKS                                                       */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="how-it-works">How It Works</h2>
      <p>
        Counters live in process memory, one per key (e.g. <code>ip:1.2.3.4</code> or{' '}
        <code>route:/api/login:1.2.3.4</code>). How a counter decides is set by{' '}
        <code>RateLimitConfig.Strategy</code>:
      </p>

      <table>
        <thead>
          <tr>
            <th>Strategy</th>
            <th>How it counts</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>sentinel.SlidingWindow</code> (default)</td>
            <td>
              Keeps the current and previous window's counts. A request is allowed while{' '}
              <code>previous × overlap + current</code> is under the limit, where <em>overlap</em> is
              how much of the previous window still falls inside the window ending now. At a boundary
              the whole previous window still counts, so a burst straddling it is limited. Rejected
              requests are not counted.
            </td>
          </tr>
          <tr>
            <td><code>sentinel.FixedWindow</code></td>
            <td>
              A window starts at a client's first request and resets completely when it ends. Cheap,
              but up to twice the limit can pass across a boundary. Rejected requests count.
            </td>
          </tr>
          <tr>
            <td><code>sentinel.TokenBucket</code></td>
            <td>
              A bucket holding up to <code>Requests</code> tokens, refilled at <code>Requests</code>{' '}
              per <code>Window</code>. Each request spends one; a burst up to the limit is allowed,
              then a steady rate.
            </td>
          </tr>
        </tbody>
      </table>

      <p>
        When a limit is exceeded the request is rejected with <code>429</code>. A background goroutine
        runs every <strong>30 seconds</strong> and removes counters that no longer affect any decision,
        preventing unbounded memory growth. An unknown strategy falls back to sliding window and is
        reported by <code>ValidateConfig</code>.
      </p>

      <Callout type="warning" title="Before v2.3.0">
        <code>Strategy</code> was never read: every limit was a fixed window whatever the config said.
        If you relied on that behavior, set <code>Strategy: sentinel.FixedWindow</code> explicitly.
      </Callout>

      <Callout type="info" title="Thread Safety">
        All counter operations are protected by a read-write mutex. Reads (checking remaining
        counts) use a read lock for concurrency, while writes (incrementing, cleanup) use an
        exclusive write lock.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  DASHBOARD MANAGEMENT                                               */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="dashboard">Dashboard Management</h2>
      <p>
        The Sentinel dashboard includes a dedicated <strong>Rate Limits</strong> page that gives you
        real-time visibility into your rate limit counters and configuration.
      </p>

      <h3>Live Counter States</h3>
      <p>
        The dashboard displays all active rate limit counters in real time. Each entry shows the
        counter key, the current request count, the window expiration time, and how many requests
        remain. Counters are automatically removed from the view when their window expires.
      </p>

      <h3>Edit Per-Route Limits</h3>
      <p>
        You can edit per-route limits directly from the dashboard without restarting your application.
        This is useful for responding to traffic spikes or adjusting thresholds after observing
        real-world patterns.
      </p>

      <h3>Reset Individual Counters</h3>
      <p>
        If a legitimate client gets rate-limited (e.g., during testing or after a deployment), you
        can reset their counter from the dashboard. This removes the specific counter key, allowing
        the client to send requests again immediately.
      </p>

      <Callout type="success" title="No Restart Required">
        Changes made through the dashboard (editing route limits, resetting counters) take effect on
        live requests immediately. Edits are validated — a non-positive window, a route without a
        leading <code>/</code>, or an unmatchable pattern is rejected with 400 and nothing changes —
        and every change is written to the audit log. Route-limit edits are not persisted: a restart
        goes back to your configured <code>ByRoute</code>. (Before v2.3.0, route-limit edits updated
        only the dashboard's copy of the config and were never enforced.)
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  TESTING                                                            */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="testing">Testing</h2>
      <p>
        You can verify rate limiting is working by sending rapid requests with <code>curl</code> and
        inspecting the response headers.
      </p>

      <h3>Check Rate Limit Headers</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Send a request and inspect rate limit headers
curl -v http://localhost:8080/api/hello 2>&1 | grep -i "x-ratelimit\\|retry-after"

# Expected output (first request):
# < X-RateLimit-Limit: 100
# < X-RateLimit-Remaining: 99`}
      />

      <h3>Hit the Rate Limit</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Send requests in a tight loop to trigger the limit
# (adjust the count based on your configured limit)
for i in $(seq 1 110); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/hello)
    echo "Request $i: HTTP $STATUS"
done

# You should see HTTP 200 for the first 100 requests,
# then HTTP 429 once the limit is exceeded.`}
      />

      <h3>Test Per-Route Limits</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Test the login endpoint (5 requests per 15 minutes)
for i in $(seq 1 7); do
    RESPONSE=$(curl -s -w "\\nHTTP %{http_code}" \\
        -X POST http://localhost:8080/api/login \\
        -H "Content-Type: application/json" \\
        -d '{"email":"test@example.com","password":"test"}')
    echo "Request $i: $RESPONSE"
done

# Requests 1-5: normal response
# Requests 6-7: HTTP 429 with Retry-After header`}
      />

      <h3>Inspect a 429 Response</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# After exceeding the limit, inspect the full 429 response
curl -v http://localhost:8080/api/hello 2>&1

# Response headers will include:
# < HTTP/1.1 429 Too Many Requests
# < X-RateLimit-Limit: 100
# < X-RateLimit-Remaining: 0
# < Retry-After: 60
#
# Response body:
# {"code":"RATE_LIMITED","error":"Rate limit exceeded"}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  ACROSS REPLICAS                                                    */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="replicas">Across Replicas</h2>
      <p>
        By default, counters live in process memory. If you run several instances behind a load
        balancer, each one counts on its own, so a client gets <code>N × limit</code> requests
        across <code>N</code> instances. To share the counters, set <code>Config.Counters</code> to
        a shared store. Every replica then counts against the same numbers:
      </p>
      <CodeBlock
        language="go"
        code={`import (
    "github.com/MUKE-coder/sentinel/v2/redisstore"
    "github.com/redis/go-redis/v9"
)

client := redis.NewClient(&redis.Options{
    Addr:        "redis:6379",
    ReadTimeout: 250 * time.Millisecond, // bound how long a request waits on Redis
})

sentinel.Mount(r, nil, sentinel.Config{
    Counters: redisstore.New(client),
    RateLimit: sentinel.RateLimitConfig{
        Enabled: true,
        ByIP:    &sentinel.Limit{Requests: 100, Window: time.Minute},
    },
})`}
      />
      <ul>
        <li>
          Each decision runs as one Lua script, so two replicas can&apos;t both take the last slot.
          All three strategies behave the same as they do in memory.
        </li>
        <li>
          If Redis is unreachable, requests are allowed rather than failed. The error is logged at
          most once a minute.
        </li>
        <li>
          If several applications share one Redis, give each one its own{' '}
          <code>redisstore.WithPrefix</code>.
        </li>
        <li>
          Per-IP limits key on the client address. Behind a load balancer, set{' '}
          <code>WAF.TrustedProxies</code>, or every request counts against the balancer&apos;s
          address.
        </li>
      </ul>
      <p>
        <code>examples/multi-replica</code> in the repository runs two replicas behind Caddy, with a
        shared Redis and Postgres.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  LIMITATIONS                                                        */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="limitations">Limitations</h2>
      <p>
        The rate limiter has a few limitations to keep in mind when planning your deployment.
      </p>

      <table>
        <thead>
          <tr>
            <th>Limitation</th>
            <th>Details</th>
            <th>Workaround</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>In-memory by default</strong></td>
            <td>
              Without <code>Config.Counters</code>, counters live in process memory. They reset when
              the application restarts, and each instance behind a load balancer counts on its own.
            </td>
            <td>
              Set <code>Config.Counters: redisstore.New(client)</code>. See{' '}
              <a href="#replicas">Across Replicas</a>.
            </td>
          </tr>
          <tr>
            <td><strong>Dashboard edits are not persisted</strong></td>
            <td>
              Route limits changed from the dashboard apply until the next restart, then the
              configured <code>ByRoute</code> takes over again.
            </td>
            <td>
              Copy a limit you want to keep into your config.
            </td>
          </tr>
        </tbody>
      </table>

      <Callout type="warning" title="Multi-Instance Deployments">
        If you deploy multiple instances behind a load balancer, be aware that each instance tracks
        rate limits independently. The effective limit per client is multiplied by the number of
        instances. Plan your per-instance limits accordingly.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  NEXT STEPS                                                         */}
      {/* ------------------------------------------------------------------ */}

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/configuration#rate-limiting">Full Configuration Reference</a> — All rate limit fields and strategies</li>
        <li><a href="/docs/auth-shield">Auth Shield</a> — Brute-force protection for login endpoints</li>
        <li><a href="/docs/waf">WAF Configuration</a> — Web Application Firewall rules and modes</li>
        <li><a href="/docs/the-dashboard">Dashboard</a> — Explore the Rate Limits page and other dashboard features</li>
      </ul>
    </>
  );
}
