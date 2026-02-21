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
            a: 'Sliding window counters track request counts within a rolling time window. When a request arrives, Sentinel checks if the window has expired and resets the counter if needed, then increments it. A background goroutine cleans up expired counters every 30 seconds.',
          },
          {
            q: 'How do I set per-route rate limits in Sentinel?',
            a: 'Use the ByRoute field with a map of route paths to Limit structs. Each key is an exact route path like /api/login, and the value specifies maximum requests and time window. Route limits are tracked per IP, so each client gets its own counter per route.',
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

    sentinel "github.com/MUKE-coder/sentinel"
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

      <Callout type="info" title="Exact Path Matching">
        Route keys must be exact paths. The path <code>/api/login</code> will not match{' '}
        <code>/api/login/</code> (trailing slash) or <code>/api/login?foo=bar</code> (query
        parameters are stripped). Use the path as it appears in your Gin route definitions.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  HOW IT WORKS                                                       */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="how-it-works">How It Works</h2>
      <p>
        Sentinel uses sliding window counters stored entirely in memory. Each counter tracks a
        request count and a window expiration timestamp.
      </p>
      <ol>
        <li>
          When a request arrives, Sentinel looks up the counter for the relevant key (e.g.,{' '}
          <code>ip:1.2.3.4</code>).
        </li>
        <li>
          If no counter exists, or the current time is past the window expiration, a new counter is
          created with a count of 1 and a window end of <code>now + Window</code>.
        </li>
        <li>
          If the counter exists and the window has not expired, the count is incremented.
        </li>
        <li>
          If the count exceeds the configured limit, the request is rejected with a{' '}
          <code>429</code> status.
        </li>
      </ol>

      <p>
        A background goroutine runs every <strong>30 seconds</strong> to clean up expired counters,
        preventing unbounded memory growth. The cleanup removes any counter whose window has passed.
      </p>

      <CodeBlock
        language="go"
        showLineNumbers={false}
        code={`// Internal counter structure (simplified)
type rateLimitEntry struct {
    count     int       // Number of requests in the current window
    windowEnd time.Time // When the current window expires
}

// Cleanup runs every 30 seconds, removing expired entries
func (rl *RateLimiter) cleanup() {
    ticker := time.NewTicker(30 * time.Second)
    for range ticker.C {
        now := time.Now()
        for key, entry := range rl.counters {
            if now.After(entry.windowEnd) {
                delete(rl.counters, key)
            }
        }
    }
}`}
      />

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
        Changes made through the dashboard (editing route limits, resetting counters) take effect
        immediately. There is no need to restart or redeploy your application.
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
      {/*  LIMITATIONS                                                        */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="limitations">Limitations</h2>
      <p>
        The current rate limiter implementation has a few limitations to be aware of when planning
        your deployment.
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
            <td><strong>In-memory only</strong></td>
            <td>
              All rate limit counters are stored in process memory. Counters are lost when the
              application restarts.
            </td>
            <td>
              Accept that counters reset on restart. For most use cases, this is acceptable because
              windows are short (minutes/hours).
            </td>
          </tr>
          <tr>
            <td><strong>No cross-instance sharing</strong></td>
            <td>
              If you run multiple instances of your application behind a load balancer, each instance
              maintains its own independent counters. A client could effectively get{' '}
              <code>N x limit</code> requests across <code>N</code> instances.
            </td>
            <td>
              Use sticky sessions at the load balancer level, or divide your limits by the number of
              instances (e.g., set 50 req/min per instance if you have 2 instances and want a 100
              req/min effective limit).
            </td>
          </tr>
          <tr>
            <td><strong>Exact path matching</strong></td>
            <td>
              Per-route limits use exact string matching on the request path. Patterns, wildcards,
              and path parameters are not supported.
            </td>
            <td>
              List each specific path you want to limit in the <code>ByRoute</code> map.
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
