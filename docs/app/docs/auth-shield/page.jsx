import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';
import { FAQSchema, TechArticleSchema, SpeakableSchema } from '@/components/JsonLd';

export const metadata = {
  title: 'Auth Shield - Sentinel Docs',
  description:
    "Protect login endpoints from brute-force attacks with Sentinel's Auth Shield. Automatic lockouts after configurable failed attempts.",
  alternates: {
    canonical: 'https://sentinel-go-sdk.vercel.app/docs/auth-shield',
  },
  openGraph: {
    title: 'Auth Shield - Sentinel Docs',
    description:
      "Protect login endpoints from brute-force attacks with Sentinel's Auth Shield. Automatic lockouts after configurable failed attempts.",
    url: 'https://sentinel-go-sdk.vercel.app/docs/auth-shield',
    type: 'article',
  },
};

export default function AuthShield() {
  return (
    <>
      <FAQSchema
        questions={[
          {
            q: 'What is Sentinel Auth Shield?',
            a: 'Auth Shield is a Sentinel middleware that protects login endpoints from brute-force attacks and credential stuffing. It monitors authentication attempts per IP, automatically locks out offending clients after repeated failures, and emits threat events into the Sentinel pipeline.',
          },
          {
            q: 'How does Auth Shield lockout work?',
            a: 'Auth Shield tracks failed login attempts (non-2xx responses) per IP within a sliding time window. When failures reach MaxFailedAttempts (default 5), the IP is locked out for LockoutDuration (default 15 minutes). Locked IPs receive HTTP 429 responses.',
          },
          {
            q: 'How do I configure the failed attempt threshold?',
            a: 'Set MaxFailedAttempts in AuthShieldConfig to your desired threshold. The default is 5 failed attempts. Pair it with LockoutDuration to control how long the lockout lasts. A successful login resets the failure counter for that IP and username to zero.',
          },
          {
            q: 'Does Auth Shield protect against credential stuffing?',
            a: 'Yes. Enable CredentialStuffingDetection in AuthShieldConfig to detect a single IP trying many different usernames (more than 10 unique usernames within the window). This triggers a high-severity CredentialStuffing threat event and can be combined with alerting.',
          },
        ]}
      />
      <TechArticleSchema
        title="Sentinel Auth Shield"
        description="Protect login endpoints from brute-force attacks with Sentinel's Auth Shield. Automatic lockouts after configurable failed attempts."
        url="https://sentinel-go-sdk.vercel.app/docs/auth-shield"
      />
      <SpeakableSchema
        url="https://sentinel-go-sdk.vercel.app/docs/auth-shield"
        cssSelector={['.prose h1', '.prose h2', '.prose p']}
      />
      <h1>Auth Shield</h1>
      <p>
        Auth Shield protects your login endpoints from brute-force attacks and credential stuffing.
        When enabled, it monitors authentication attempts per IP, automatically locks out offending
        clients after repeated failures, and emits threat events into the Sentinel pipeline.
      </p>

      <Callout type="info" title="How It Differs from Rate Limiting">
        Rate limiting controls overall request volume. Auth Shield is purpose-built for login
        endpoints — it tracks <strong>failed authentication outcomes</strong> (non-2xx responses),
        not just request counts. A legitimate user who logs in successfully on the first try is
        never affected.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  CONFIGURATION                                                     */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="configuration">Configuration</h2>
      <p>
        Auth Shield is configured through the <code>AuthShieldConfig</code> section of{' '}
        <code>sentinel.Config</code>. All fields have sensible defaults except{' '}
        <code>LoginRoute</code>, which must match your actual login endpoint path.
      </p>

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
            <td>Enables the Auth Shield middleware.</td>
          </tr>
          <tr>
            <td><code>LoginRoute</code></td>
            <td><code>string</code></td>
            <td><code>""</code></td>
            <td>The exact path of your login endpoint (e.g., <code>/api/login</code>). Must match the route registered in Gin.</td>
          </tr>
          <tr>
            <td><code>MaxFailedAttempts</code></td>
            <td><code>int</code></td>
            <td><code>5</code></td>
            <td>Number of failed login attempts within the lockout window before the IP is locked out.</td>
          </tr>
          <tr>
            <td><code>LockoutDuration</code></td>
            <td><code>time.Duration</code></td>
            <td><code>15 * time.Minute</code></td>
            <td>How long an IP remains locked out after exceeding <code>MaxFailedAttempts</code>. Also used as the sliding window for counting failures.</td>
          </tr>
          <tr>
            <td><code>CredentialStuffingDetection</code></td>
            <td><code>bool</code></td>
            <td><code>false</code></td>
            <td>When enabled, detects a single IP trying many different usernames (more than 10 unique usernames within the window).</td>
          </tr>
          <tr>
            <td><code>BruteForceDetection</code></td>
            <td><code>bool</code></td>
            <td><code>false</code></td>
            <td>When enabled, detects repeated password guessing against the same username.</td>
          </tr>
        </tbody>
      </table>

      {/* ------------------------------------------------------------------ */}
      {/*  HOW IT WORKS                                                      */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="how-it-works">How It Works</h2>
      <p>
        Auth Shield registers as Gin middleware and intercepts only <code>POST</code> requests to
        the configured <code>LoginRoute</code>. All other routes and HTTP methods pass through
        untouched. The flow is:
      </p>
      <ol>
        <li>
          <strong>Pre-check</strong> — Before your login handler runs, Auth Shield checks if the
          client IP is currently locked out. If it is, the request is immediately rejected with
          a <code>429 Too Many Requests</code> response.
        </li>
        <li>
          <strong>Passthrough</strong> — If the IP is not locked, the request proceeds to your
          login handler as normal.
        </li>
        <li>
          <strong>Observe response</strong> — After your handler responds, Auth Shield inspects
          the HTTP status code:
          <ul>
            <li><strong>2xx</strong> — Successful login. The failure counter for that IP (and username, if provided) is reset to zero.</li>
            <li><strong>4xx</strong> — Failed login. The failure is recorded with a timestamp.</li>
          </ul>
        </li>
        <li>
          <strong>Lockout</strong> — If the number of failures from an IP within the{' '}
          <code>LockoutDuration</code> window reaches <code>MaxFailedAttempts</code>, the IP is
          locked out for the full <code>LockoutDuration</code>.
        </li>
      </ol>

      <Callout type="warning" title="LoginRoute Must Match Exactly">
        The <code>LoginRoute</code> must be the exact path string of your login handler (e.g.,{' '}
        <code>/api/login</code>). It is compared against <code>c.Request.URL.Path</code>. If it
        does not match, Auth Shield will not intercept the request and no failures will be tracked.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  EXAMPLE CONFIG                                                    */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="example">Example Configuration</h2>
      <p>
        A typical production setup with 5 allowed attempts and a 15-minute lockout:
      </p>
      <CodeBlock
        language="go"
        filename="main.go"
        code={`package main

import (
    "time"

    sentinel "github.com/MUKE-coder/sentinel"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

    sentinel.Mount(r, nil, sentinel.Config{
        AuthShield: sentinel.AuthShieldConfig{
            Enabled:                    true,
            LoginRoute:                 "/api/login",
            MaxFailedAttempts:          5,
            LockoutDuration:            15 * time.Minute,
            CredentialStuffingDetection: true,
            BruteForceDetection:        true,
        },
    })

    r.POST("/api/login", func(c *gin.Context) {
        // Your login logic here
        username := c.PostForm("username")
        password := c.PostForm("password")

        // Optionally set the username so Auth Shield can track per-user failures
        c.Set("sentinel_username", username)

        if username == "admin" && password == "correct-password" {
            c.JSON(200, gin.H{"token": "jwt-token-here"})
        } else {
            c.JSON(401, gin.H{"error": "Invalid credentials"})
        }
    })

    r.Run(":8080")
}`}
      />

      <Callout type="info" title="Username Tracking">
        To enable per-username failure tracking and credential stuffing detection, set{' '}
        <code>c.Set("sentinel_username", username)</code> in your login handler before writing the
        response. Auth Shield reads this value from the Gin context. If not set, only IP-based
        tracking is used.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  WHAT GETS TRACKED                                                 */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="tracking">What Gets Tracked</h2>
      <p>
        Auth Shield determines success or failure based on the HTTP status code returned by your
        login handler:
      </p>
      <table>
        <thead>
          <tr>
            <th>Status Code</th>
            <th>Interpretation</th>
            <th>Action</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>200-299</code></td>
            <td>Successful login</td>
            <td>Reset all failure counters for the IP and username.</td>
          </tr>
          <tr>
            <td><code>400-499</code></td>
            <td>Failed login</td>
            <td>Increment the failure counter. Lock the IP if <code>MaxFailedAttempts</code> is reached.</td>
          </tr>
          <tr>
            <td><code>500+</code></td>
            <td>Server error</td>
            <td>Ignored. Server errors are not counted as failed login attempts.</td>
          </tr>
        </tbody>
      </table>
      <p>
        Failure timestamps older than <code>LockoutDuration</code> are automatically pruned from
        the sliding window, so a slow trickle of failures over a long period will not trigger a
        lockout.
      </p>

      <Callout type="success" title="Design Your Login Handler Accordingly">
        Return a <code>401</code> for invalid credentials and a <code>200</code> for successful
        logins. Avoid returning <code>200</code> with an error in the body, as Auth Shield will
        treat it as a success and reset the counter.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  LOCKOUT RESPONSE                                                  */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="lockout-response">Lockout Response</h2>
      <p>
        When a locked-out IP attempts to access the login route, Auth Shield returns the following
        response without invoking your login handler:
      </p>
      <CodeBlock
        language="json"
        filename="429 Too Many Requests"
        showLineNumbers={false}
        code={`{
  "error": "Too many failed login attempts. Please try again later.",
  "code": "AUTH_SHIELD_LOCKED"
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  EVENTS                                                            */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="events">Events</h2>
      <p>
        Auth Shield emits threat events into the Sentinel pipeline whenever a lockout is triggered
        or credential stuffing is detected. These events flow through the same pipeline as WAF and
        anomaly events, meaning they are:
      </p>
      <ul>
        <li>Stored in the configured storage backend</li>
        <li>Visible in the dashboard Threats page</li>
        <li>Eligible for alerting (Slack, email, webhook) based on severity</li>
        <li>Available for AI analysis if an AI provider is configured</li>
      </ul>

      <h3>Threat Event Types</h3>
      <table>
        <thead>
          <tr>
            <th>Threat Type</th>
            <th>Trigger</th>
            <th>Severity</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>BruteForce</code></td>
            <td>IP locked out after exceeding <code>MaxFailedAttempts</code></td>
            <td>High</td>
          </tr>
          <tr>
            <td><code>CredentialStuffing</code></td>
            <td>Single IP tries more than 10 different usernames within the window</td>
            <td>High</td>
          </tr>
        </tbody>
      </table>

      <p>
        Each event includes the offending IP, the login route path, a confidence score of 90, and
        evidence detailing the specific detection pattern.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  TESTING                                                           */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="testing">Testing</h2>
      <p>
        You can verify Auth Shield is working by sending failed login requests and observing the
        lockout behavior. The following example assumes the default configuration with 5 max
        attempts.
      </p>

      <h3>Trigger a Lockout</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Send 5 failed login attempts (invalid credentials)
for i in $(seq 1 5); do
  echo "Attempt $i:"
  curl -s -o /dev/null -w "HTTP %{http_code}" \\
    -X POST http://localhost:8080/api/login \\
    -d "username=admin&password=wrong"
  echo ""
done

# Attempt 1-5: HTTP 401 (failed login, counter incrementing)
# After 5 failures, the IP is now locked out.`}
      />

      <h3>Verify the Lockout</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# The 6th attempt should return 429 (locked out)
curl -s -w "\\nHTTP %{http_code}\\n" \\
  -X POST http://localhost:8080/api/login \\
  -d "username=admin&password=wrong"

# Expected output:
# {"error":"Too many failed login attempts. Please try again later.","code":"AUTH_SHIELD_LOCKED"}
# HTTP 429`}
      />

      <h3>Verify Successful Login Still Works (from a different IP)</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Even correct credentials from the locked IP are rejected
curl -s -w "\\nHTTP %{http_code}\\n" \\
  -X POST http://localhost:8080/api/login \\
  -d "username=admin&password=correct-password"

# HTTP 429 (still locked — must wait for LockoutDuration to expire)`}
      />

      <Callout type="warning" title="Testing Locally">
        When testing locally, all requests come from <code>127.0.0.1</code> or <code>::1</code>,
        so they share a single IP counter. To test with different IPs, use the{' '}
        <code>X-Forwarded-For</code> header if your setup supports it, or test from different
        machines.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  DASHBOARD                                                         */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="dashboard">Dashboard</h2>
      <p>
        Auth Shield events appear in the Sentinel dashboard on the <strong>Threats</strong> page.
        Each event includes:
      </p>
      <ul>
        <li>Threat type displayed as <code>BruteForce</code> or <code>CredentialStuffing</code></li>
        <li>The offending IP address</li>
        <li>Timestamp of when the lockout was triggered</li>
        <li>Severity level (High)</li>
        <li>Evidence showing the detection pattern and location (<code>auth_shield</code>)</li>
      </ul>
      <p>
        You can filter the Threats page by type to isolate brute-force and credential stuffing
        events. If alerting is configured with a minimum severity of <code>High</code> or lower,
        these events will also trigger Slack, email, or webhook notifications.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  COMBINING WITH RATE LIMITING                                      */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="combining">Combining with Rate Limiting</h2>
      <p>
        Auth Shield and rate limiting are complementary. A recommended pattern is to use both:
      </p>
      <CodeBlock
        language="go"
        filename="config.go"
        code={`sentinel.Config{
    // Auth Shield: locks out IPs after failed login attempts
    AuthShield: sentinel.AuthShieldConfig{
        Enabled:                    true,
        LoginRoute:                 "/api/login",
        MaxFailedAttempts:          5,
        LockoutDuration:            15 * time.Minute,
        CredentialStuffingDetection: true,
        BruteForceDetection:        true,
    },

    // Rate Limiting: caps overall request volume to the login route
    RateLimit: sentinel.RateLimitConfig{
        Enabled: true,
        ByRoute: map[string]sentinel.Limit{
            "/api/login": {Requests: 10, Window: 15 * time.Minute},
        },
    },
}`}
      />
      <p>
        In this setup, rate limiting prevents any IP from making more than 10 requests to the
        login route in 15 minutes (regardless of success or failure), while Auth Shield specifically
        tracks authentication failures and locks out after 5 failed attempts.
      </p>

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/configuration">Configuration Reference</a> — Full list of all configuration options</li>
        <li><a href="/docs/rate-limiting">Rate Limiting</a> — Per-IP, per-user, and per-route rate limits</li>
        <li><a href="/docs/anomaly-detection">Anomaly Detection</a> — Behavioral analysis including credential stuffing patterns</li>
        <li><a href="/docs/alerting">Alerting</a> — Get notified when brute-force attacks are detected</li>
        <li><a href="/docs/the-dashboard">Dashboard</a> — Explore the Threats page and other security views</li>
      </ul>
    </>
  );
}
