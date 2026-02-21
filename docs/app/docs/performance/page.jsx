import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';
import { FAQSchema, TechArticleSchema, SpeakableSchema } from '@/components/JsonLd';

export const metadata = {
  title: 'Performance Monitoring - Sentinel Docs',
  description:
    'Track per-route latency (p50/p95/p99), error rates, and response sizes with Sentinel\'s performance monitoring middleware for Go/Gin.',
  alternates: {
    canonical: 'https://sentinel-go-sdk.vercel.app/docs/performance',
  },
  openGraph: {
    title: 'Performance Monitoring - Sentinel Docs',
    description:
      'Track per-route latency (p50/p95/p99), error rates, and response sizes with Sentinel\'s performance monitoring middleware for Go/Gin.',
    url: 'https://sentinel-go-sdk.vercel.app/docs/performance',
    siteName: 'Sentinel',
    type: 'article',
  },
};

export default function PerformanceMonitoring() {
  return (
    <>
      <FAQSchema
        faqs={[
          {
            question: 'What metrics does Sentinel performance monitoring track?',
            answer: 'Sentinel tracks per-route latency percentiles (p50, p95, p99), error rates based on 5xx status codes, throughput in requests per second, average response body size, and slow request counts. All metrics are computed both per-route and system-wide.',
          },
          {
            question: 'What latency percentiles does Sentinel provide?',
            answer: 'Sentinel computes p50 (median), p95 (tail performance), and p99 (worst-case excluding outliers) latency percentiles. These are maintained per route and globally, giving you precise visibility into how each endpoint performs under real traffic.',
          },
          {
            question: 'How do I set a slow request threshold in Sentinel?',
            answer: 'Set the SlowRequestThreshold field in PerformanceConfig to any time.Duration value. For example, 500 * time.Millisecond or 2 * time.Second. Requests exceeding this duration are flagged as slow in both the API metrics and the dashboard.',
          },
          {
            question: 'Does Sentinel performance monitoring add overhead to requests?',
            answer: 'Sentinel adds negligible overhead. It uses nanosecond-precision timing around your handlers and emits metrics to an async pipeline via a non-blocking send. If the pipeline buffer is full, the metric is dropped rather than stalling the response.',
          },
        ]}
      />
      <TechArticleSchema
        title="Performance Monitoring - Sentinel Docs"
        description="Track per-route latency (p50/p95/p99), error rates, and response sizes with Sentinel's performance monitoring middleware for Go/Gin."
        url="https://sentinel-go-sdk.vercel.app/docs/performance"
      />
      <SpeakableSchema url="https://sentinel-go-sdk.vercel.app/docs/performance" />

      <h1>Performance Monitoring</h1>
      <p>
        Sentinel automatically tracks per-route latency and throughput using lightweight middleware.
        Every HTTP request is measured — no manual instrumentation required. Metrics are aggregated
        in memory and exposed via API endpoints and the built-in dashboard.
      </p>

      <Callout type="info" title="Always On">
        Performance monitoring is enabled by default when Sentinel is mounted. The middleware adds
        negligible overhead (nanosecond-precision timing around your handlers). Configure{' '}
        <code>PerformanceConfig</code> to tune slow-request thresholds and retention.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  WHAT GETS TRACKED                                                  */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="what-gets-tracked">What Gets Tracked</h2>
      <p>
        The performance middleware captures the following data points for every request:
      </p>

      <table>
        <thead>
          <tr>
            <th>Data Point</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>Duration</code></td>
            <td>Total time from request received to response written, measured with <code>time.Since</code>.</td>
          </tr>
          <tr>
            <td><code>StatusCode</code></td>
            <td>HTTP status code returned to the client.</td>
          </tr>
          <tr>
            <td><code>ResponseSize</code></td>
            <td>Size of the response body in bytes.</td>
          </tr>
          <tr>
            <td><code>Method</code></td>
            <td>HTTP method (<code>GET</code>, <code>POST</code>, etc.).</td>
          </tr>
          <tr>
            <td><code>Path</code></td>
            <td>Request path, used for per-route aggregation.</td>
          </tr>
        </tbody>
      </table>

      {/* ------------------------------------------------------------------ */}
      {/*  CONFIGURATION                                                      */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="configuration">Configuration</h2>
      <p>
        Customize performance monitoring through <code>PerformanceConfig</code>. The only tunable
        field is the slow-request threshold — everything else works out of the box.
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
        Performance: sentinel.PerformanceConfig{
            SlowRequestThreshold: 2 * time.Second,
        },
    })

    r.GET("/api/data", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })

    r.Run(":8080")
}`}
      />

      <h3>PerformanceConfig Reference</h3>
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
            <td><code>SlowRequestThreshold</code></td>
            <td><code>time.Duration</code></td>
            <td><code>1 * time.Second</code></td>
            <td>Requests exceeding this duration are flagged as slow in metrics and the dashboard.</td>
          </tr>
        </tbody>
      </table>

      {/* ------------------------------------------------------------------ */}
      {/*  METRICS                                                            */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="metrics">Metrics</h2>
      <p>
        Sentinel computes the following aggregate metrics from collected request data. Metrics are
        maintained per route and system-wide.
      </p>

      <table>
        <thead>
          <tr>
            <th>Metric</th>
            <th>Scope</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>p50</code></td>
            <td>Per-route / Global</td>
            <td>Median latency — 50th percentile of request durations.</td>
          </tr>
          <tr>
            <td><code>p95</code></td>
            <td>Per-route / Global</td>
            <td>95th percentile latency — captures tail performance.</td>
          </tr>
          <tr>
            <td><code>p99</code></td>
            <td>Per-route / Global</td>
            <td>99th percentile latency — worst-case excluding extreme outliers.</td>
          </tr>
          <tr>
            <td><code>errorRate</code></td>
            <td>Per-route / Global</td>
            <td>Percentage of requests returning 5xx status codes.</td>
          </tr>
          <tr>
            <td><code>throughput</code></td>
            <td>Per-route / Global</td>
            <td>Requests per second over the most recent measurement window.</td>
          </tr>
          <tr>
            <td><code>avgResponseSize</code></td>
            <td>Per-route</td>
            <td>Average response body size in bytes.</td>
          </tr>
          <tr>
            <td><code>slowRequests</code></td>
            <td>Per-route / Global</td>
            <td>Count of requests exceeding <code>SlowRequestThreshold</code>.</td>
          </tr>
        </tbody>
      </table>

      {/* ------------------------------------------------------------------ */}
      {/*  API ENDPOINTS                                                      */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="api">API Endpoints</h2>
      <p>
        Performance data is available through two REST endpoints served by the Sentinel dashboard
        router.
      </p>

      <h3>System Overview</h3>
      <p>
        Returns a high-level snapshot of system-wide performance metrics.
      </p>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`GET /sentinel/api/performance/overview`}
      />
      <CodeBlock
        language="json"
        filename="response"
        code={`{
    "totalRequests": 48210,
    "avgResponseTime": "12ms",
    "p50": "8ms",
    "p95": "45ms",
    "p99": "120ms",
    "errorRate": 0.023,
    "throughput": 82.5,
    "slowRequests": 37
}`}
      />

      <h3>Per-Route Breakdown</h3>
      <p>
        Returns latency, throughput, and error metrics broken down by route.
      </p>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`GET /sentinel/api/performance/routes`}
      />
      <CodeBlock
        language="json"
        filename="response"
        code={`{
    "routes": [
        {
            "method": "GET",
            "path": "/api/users",
            "totalRequests": 12400,
            "avgDuration": "15ms",
            "p50": "10ms",
            "p95": "52ms",
            "p99": "140ms",
            "errorRate": 0.01,
            "throughput": 21.3,
            "avgResponseSize": 2048,
            "slowRequests": 8
        },
        {
            "method": "POST",
            "path": "/api/orders",
            "totalRequests": 3500,
            "avgDuration": "85ms",
            "p50": "60ms",
            "p95": "210ms",
            "p99": "450ms",
            "errorRate": 0.04,
            "throughput": 6.1,
            "avgResponseSize": 512,
            "slowRequests": 12
        }
    ]
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  DASHBOARD                                                          */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="dashboard">Dashboard</h2>
      <p>
        The Sentinel dashboard includes a dedicated <strong>Performance</strong> page that displays
        a sortable route metrics table. Each row shows a route's method, path, request count,
        latency percentiles (p50 / p95 / p99), error rate, throughput, and slow request count.
        Use the table to identify your slowest and most error-prone endpoints at a glance.
      </p>

      <Callout type="success" title="Real-Time Updates">
        The performance dashboard refreshes automatically. Metrics update as new requests are
        processed — no manual polling required.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  SLOW REQUEST DETECTION                                             */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="slow-request-detection">Slow Request Detection</h2>
      <p>
        Any request whose duration exceeds <code>SlowRequestThreshold</code> is flagged as a slow
        request. Slow requests are counted separately in both the system overview and per-route
        metrics, making it easy to spot routes that need optimization.
      </p>

      <CodeBlock
        language="go"
        showLineNumbers={false}
        code={`// Flag requests taking longer than 500ms
Performance: sentinel.PerformanceConfig{
    SlowRequestThreshold: 500 * time.Millisecond,
}

// Flag requests taking longer than 3 seconds
Performance: sentinel.PerformanceConfig{
    SlowRequestThreshold: 3 * time.Second,
}`}
      />

      <Callout type="warning" title="Threshold Tuning">
        Set the threshold based on your application's performance expectations. A value that is too
        low floods the slow request count with noise; too high and genuinely slow endpoints go
        unnoticed. Start with <code>1 * time.Second</code> and adjust after observing real traffic.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  HOW IT WORKS                                                       */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="how-it-works">How It Works</h2>
      <p>
        Performance monitoring is implemented as Gin middleware that wraps every request handler.
      </p>

      <ol>
        <li>
          <strong>Before handler</strong> — The middleware records <code>time.Now()</code> as the
          start time.
        </li>
        <li>
          <strong>Handler executes</strong> — The request is passed through to your route handler
          via <code>c.Next()</code>.
        </li>
        <li>
          <strong>After handler</strong> — The middleware computes the duration
          (<code>time.Since(start)</code>), captures the status code and response size, and builds
          a <code>PerformanceMetric</code> struct.
        </li>
        <li>
          <strong>Pipeline emission</strong> — The metric is emitted to Sentinel's async event
          pipeline via a non-blocking send. This decouples metric aggregation from request
          handling, adding no meaningful latency.
        </li>
        <li>
          <strong>Aggregation</strong> — A pipeline handler receives the metric and updates
          in-memory aggregates: increments request counters, inserts the duration into a percentile
          sketch, updates error counts, and checks against <code>SlowRequestThreshold</code>.
        </li>
      </ol>

      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Request lifecycle with performance monitoring:
#
# Request ──> Middleware records start time
#                 │
#                 v
#             c.Next() ──> Your handler runs
#                 │
#                 v
#             Compute duration, status, size
#                 │
#                 v
#             Emit PerformanceMetric to pipeline (non-blocking)
#                 │
#                 v
#             Response sent to client
#
# Pipeline (async):
#   PerformanceMetric ──> Update aggregates
#                             ├── Percentile sketch (p50/p95/p99)
#                             ├── Error rate counter
#                             ├── Throughput counter
#                             └── Slow request check`}
      />

      <Callout type="info" title="Zero Latency Impact">
        The metric emission is non-blocking. If the pipeline buffer is full, the metric is dropped
        rather than stalling the response. Under normal operation, no metrics are lost.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  NEXT STEPS                                                         */}
      {/* ------------------------------------------------------------------ */}

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/configuration">Configuration Reference</a> — Full PerformanceConfig field reference</li>
        <li><a href="/docs/anomaly-detection">Anomaly Detection</a> — Detect unusual traffic patterns using behavioral baselines</li>
        <li><a href="/docs/rate-limiting">Rate Limiting</a> — Throttle excessive traffic before it impacts performance</li>
        <li><a href="/docs/the-dashboard">Dashboard</a> — Explore the Performance page and other dashboard features</li>
      </ul>
    </>
  );
}
