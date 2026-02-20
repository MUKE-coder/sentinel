import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';

export const metadata = { title: 'Anomaly Detection - Sentinel Docs' };

export default function AnomalyDetection() {
  return (
    <>
      <h1>Anomaly Detection</h1>
      <p>
        Sentinel includes a statistical anomaly detection system that identifies unusual traffic
        patterns by comparing real-time user activity against learned behavioral baselines. Unlike
        the WAF, which matches known attack signatures, anomaly detection catches previously unseen
        threats by flagging activity that deviates from what is normal for each user.
      </p>
      <p>
        The detector builds per-user baselines from historical activity data — typical active hours,
        frequently accessed routes, source IPs, geographic locations, and request velocity. When new
        activity diverges significantly from these baselines, Sentinel emits a threat event with type{' '}
        <code>AnomalyDetected</code>.
      </p>

      <Callout type="info" title="Requires a UserExtractor">
        Anomaly detection operates on a per-user basis. You must configure a{' '}
        <code>UserExtractor</code> in your Sentinel config so the system can associate requests with
        user identities. Without it, the anomaly detector has no user context and will not run.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  CONFIGURATION                                                      */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="configuration">Configuration</h2>
      <p>
        Anomaly detection is disabled by default. Enable it by setting <code>Enabled: true</code> in
        your <code>AnomalyConfig</code>. The minimal configuration uses all defaults:
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
        Anomaly: sentinel.AnomalyConfig{
            Enabled:    true,
            Sensitivity: sentinel.AnomalySensitivityMedium,
        },
        UserExtractor: func(c *gin.Context) *sentinel.UserContext {
            return &sentinel.UserContext{
                ID:    c.GetHeader("X-User-ID"),
                Email: c.GetHeader("X-User-Email"),
                Role:  c.GetHeader("X-User-Role"),
            }
        },
    })

    r.GET("/api/data", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })

    r.Run(":8080")
}`}
      />

      <h3>AnomalyConfig Reference</h3>
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
            <td>Enables anomaly detection. When false, the detector is a no-op.</td>
          </tr>
          <tr>
            <td><code>Sensitivity</code></td>
            <td><code>AnomalySensitivity</code></td>
            <td><code>AnomalySensitivityMedium</code></td>
            <td>Controls the scoring threshold that triggers an anomaly event. See sensitivity levels below.</td>
          </tr>
          <tr>
            <td><code>LearningPeriod</code></td>
            <td><code>time.Duration</code></td>
            <td><code>7 * 24 * time.Hour</code></td>
            <td>How far back to look when computing a user's behavioral baseline. Longer periods produce more stable baselines but are slower to adapt.</td>
          </tr>
          <tr>
            <td><code>Checks</code></td>
            <td><code>[]AnomalyCheckType</code></td>
            <td>All checks enabled</td>
            <td>Which anomaly checks to run. If empty, all check types are enabled. Specify a subset to narrow detection scope.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="config.go"
        code={`Anomaly: sentinel.AnomalyConfig{
    Enabled:        true,
    Sensitivity:    sentinel.AnomalySensitivityMedium,
    LearningPeriod: 14 * 24 * time.Hour, // 2 weeks of history
    Checks: []sentinel.AnomalyCheckType{
        sentinel.CheckOffHoursAccess,
        sentinel.CheckUnusualAccess,
        sentinel.CheckVelocityAnomaly,
        sentinel.CheckImpossibleTravel,
        sentinel.CheckDataExfiltration,
    },
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  SENSITIVITY LEVELS                                                 */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="sensitivity">Sensitivity Levels</h2>
      <p>
        Sensitivity controls the anomaly score threshold required to emit a threat event. Each
        anomaly check contributes a score, and the total is compared against the threshold. Lower
        thresholds trigger more alerts.
      </p>

      <table>
        <thead>
          <tr>
            <th>Level</th>
            <th>Constant</th>
            <th>Threshold</th>
            <th>Behavior</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Low</td>
            <td><code>sentinel.AnomalySensitivityLow</code></td>
            <td>50</td>
            <td>Only the most significant anomalies trigger events. Fewer alerts, less noise. Best for high-traffic applications where some deviation is normal.</td>
          </tr>
          <tr>
            <td>Medium</td>
            <td><code>sentinel.AnomalySensitivityMedium</code></td>
            <td>30</td>
            <td>Balanced detection. Catches meaningful deviations without overwhelming you with alerts. Recommended starting point.</td>
          </tr>
          <tr>
            <td>High</td>
            <td><code>sentinel.AnomalySensitivityHigh</code></td>
            <td>15</td>
            <td>Aggressive detection. Catches subtle anomalies but produces more alerts. Best for high-security environments or during active incident investigation.</td>
          </tr>
        </tbody>
      </table>

      <Callout type="success" title="Recommended Starting Point">
        Start with <code>AnomalySensitivityMedium</code>. Monitor the anomaly events in the
        dashboard for a week to understand your application's normal patterns, then adjust up or
        down based on the signal-to-noise ratio you observe.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  WHAT GETS DETECTED                                                 */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="checks">What Gets Detected</h2>
      <p>
        The anomaly detector runs a configurable set of behavioral checks against each user activity
        event. Each check compares one aspect of the current request against the user's baseline and
        returns a score from 0 (normal) to 30 (highly anomalous). Scores from all checks are summed
        (capped at 100) and compared against the sensitivity threshold.
      </p>

      <table>
        <thead>
          <tr>
            <th>Check</th>
            <th>Constant</th>
            <th>Max Score</th>
            <th>What It Detects</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Off-Hours Access</td>
            <td><code>CheckOffHoursAccess</code></td>
            <td>30</td>
            <td>Activity during hours when the user is rarely active. If the current hour represents less than 1% of baseline activity, the full score is assigned; less than 3% yields a partial score of 15.</td>
          </tr>
          <tr>
            <td>Unusual Route Access</td>
            <td><code>CheckUnusualAccess</code></td>
            <td>25</td>
            <td>Access to routes (method + path) that the user has never accessed before during the learning period. Useful for detecting lateral movement or account compromise.</td>
          </tr>
          <tr>
            <td>Velocity Anomaly</td>
            <td><code>CheckVelocityAnomaly</code></td>
            <td>25</td>
            <td>Request rate spikes that exceed 3x the user's average rate for the current time of day. Catches automated scraping, credential stuffing, or bot activity on a compromised account.</td>
          </tr>
          <tr>
            <td>Impossible Travel</td>
            <td><code>CheckImpossibleTravel</code></td>
            <td>30</td>
            <td>Activity from a new IP address, especially from a country the user has never connected from. A new country yields a score of 30; a new IP in the same country yields 10.</td>
          </tr>
          <tr>
            <td>Data Exfiltration</td>
            <td><code>CheckDataExfiltration</code></td>
            <td>20</td>
            <td>Unusually large response sizes or durations that exceed 5x the user's baseline average. Indicates potential bulk data extraction.</td>
          </tr>
          <tr>
            <td>Credential Stuffing</td>
            <td><code>CheckCredentialStuffing</code></td>
            <td>--</td>
            <td>Reserved check type for detecting credential stuffing patterns. Configure via Auth Shield for full brute-force protection.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        showLineNumbers={false}
        code={`// Enable only specific checks
Checks: []sentinel.AnomalyCheckType{
    sentinel.CheckOffHoursAccess,
    sentinel.CheckImpossibleTravel,
    // Omit checks that are not relevant to your application
}`}
      />

      <Callout type="warning" title="Minimum Baseline Requirement">
        The anomaly detector requires at least <strong>10 historical activity records</strong> for a
        user before it will evaluate checks. Users with fewer records are silently skipped. This
        prevents false positives on new users or accounts with very little history.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  HOW IT WORKS                                                       */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="how-it-works">How It Works</h2>
      <p>
        The anomaly detector operates as a handler in Sentinel's asynchronous event pipeline. It
        does not sit in the HTTP request path and adds no latency to your responses.
      </p>

      <ol>
        <li>
          <strong>Activity Tracking</strong> — When a request arrives, Sentinel records a{' '}
          <code>UserActivity</code> event containing the user ID, timestamp, IP address, HTTP
          method, path, response duration, and geographic country (if geo is enabled).
        </li>
        <li>
          <strong>Pipeline Dispatch</strong> — The activity event is sent to the async pipeline via
          a non-blocking ring buffer. This decouples detection from request handling.
        </li>
        <li>
          <strong>Baseline Computation</strong> — The detector loads the user's historical activity
          from storage (within the configured <code>LearningPeriod</code>) and computes a{' '}
          <code>UserBaseline</code>. Baselines are cached for 1 hour to avoid repeated computation.
        </li>
        <li>
          <strong>Check Evaluation</strong> — Each enabled check compares the current activity
          against the baseline and returns a score. Scores are summed and capped at 100.
        </li>
        <li>
          <strong>Threshold Comparison</strong> — If the total score meets or exceeds the
          sensitivity threshold, a <code>ThreatEvent</code> is emitted with type{' '}
          <code>AnomalyDetected</code>.
        </li>
        <li>
          <strong>Event Processing</strong> — The threat event flows through the rest of the
          pipeline: it is persisted to storage, updates the threat actor profile, recalculates the
          security score, and triggers alerts if the severity meets the alerting threshold.
        </li>
      </ol>

      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Anomaly detection flow:
#
# HTTP Request ──> Record UserActivity ──> Async Pipeline
#       │                                       │
#       v                                       v
#   Response sent                    Load/Compute Baseline
#   (no added latency)                          │
#                                               v
#                                    Run Checks (score each)
#                                               │
#                                    ┌──────────┴──────────┐
#                                    v                      v
#                              Score < Threshold      Score >= Threshold
#                                    │                      │
#                                    v                      v
#                                No action           Emit ThreatEvent
#                                                          │
#                                                          v
#                                                  Persist + Alert`}
      />

      <Callout type="info" title="Non-Blocking Detection">
        The anomaly detector runs entirely outside the HTTP request path. Activity recording uses a
        non-blocking ring buffer, so detection never slows down your API responses, even when
        computing baselines from large activity histories.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  BASELINE DETAILS                                                   */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="baselines">Baselines</h2>
      <p>
        A <code>UserBaseline</code> captures the behavioral profile for a single user. It is
        computed from all activity within the <code>LearningPeriod</code> and cached in memory for
        1 hour before being recomputed.
      </p>

      <table>
        <thead>
          <tr>
            <th>Baseline Field</th>
            <th>What It Tracks</th>
            <th>Used By</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>ActiveHours</code></td>
            <td>Distribution of activity across hours of the day (0-23)</td>
            <td><code>CheckOffHoursAccess</code></td>
          </tr>
          <tr>
            <td><code>TypicalRoutes</code></td>
            <td>Set of method+path combinations the user has accessed</td>
            <td><code>CheckUnusualAccess</code></td>
          </tr>
          <tr>
            <td><code>AvgRequestsPerHour</code></td>
            <td>Average request rate across the learning period</td>
            <td><code>CheckVelocityAnomaly</code></td>
          </tr>
          <tr>
            <td><code>SourceIPs</code></td>
            <td>Set of IP addresses the user has connected from</td>
            <td><code>CheckImpossibleTravel</code></td>
          </tr>
          <tr>
            <td><code>Countries</code></td>
            <td>Set of countries (by geo lookup) the user has connected from</td>
            <td><code>CheckImpossibleTravel</code></td>
          </tr>
          <tr>
            <td><code>AvgResponseSize</code></td>
            <td>Average response duration/size across the learning period</td>
            <td><code>CheckDataExfiltration</code></td>
          </tr>
        </tbody>
      </table>

      <p>
        The <code>LearningPeriod</code> determines the time window for baseline computation. The
        default is 7 days. A longer period (e.g., 14 or 30 days) produces more stable baselines but
        adapts more slowly to legitimate changes in user behavior.
      </p>

      <CodeBlock
        language="go"
        showLineNumbers={false}
        code={`// Short learning period — adapts quickly, less stable
LearningPeriod: 3 * 24 * time.Hour,  // 3 days

// Default — balanced
LearningPeriod: 7 * 24 * time.Hour,  // 7 days

// Long learning period — very stable, slow to adapt
LearningPeriod: 30 * 24 * time.Hour, // 30 days`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  EVENTS                                                             */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="events">Anomaly Events</h2>
      <p>
        When an anomaly is detected, Sentinel emits a <code>ThreatEvent</code> with the threat type{' '}
        <code>AnomalyDetected</code>. These events appear in the dashboard alongside WAF detections
        and other security events.
      </p>

      <table>
        <thead>
          <tr>
            <th>Event Field</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>ThreatTypes</code></td>
            <td><code>["AnomalyDetected"]</code></td>
          </tr>
          <tr>
            <td><code>Severity</code></td>
            <td>Computed from the anomaly score: Critical (&ge;80), High (&ge;60), Medium (&ge;30), Low (&lt;30)</td>
          </tr>
          <tr>
            <td><code>Confidence</code></td>
            <td>The raw anomaly score (0-100), representing how far the activity deviates from baseline</td>
          </tr>
          <tr>
            <td><code>Evidence</code></td>
            <td>Contains the anomaly score and the list of checks that contributed to it</td>
          </tr>
          <tr>
            <td><code>Blocked</code></td>
            <td><code>false</code> — anomaly events are informational; they do not block requests</td>
          </tr>
        </tbody>
      </table>

      <h3>Severity Mapping</h3>
      <p>
        The anomaly score is mapped to a severity level using the following thresholds:
      </p>
      <table>
        <thead>
          <tr>
            <th>Score Range</th>
            <th>Severity</th>
            <th>Interpretation</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>80 - 100</td>
            <td><code>Critical</code></td>
            <td>Multiple strong anomaly signals. Very likely a compromised account or active attack.</td>
          </tr>
          <tr>
            <td>60 - 79</td>
            <td><code>High</code></td>
            <td>Significant deviation from baseline. Warrants immediate investigation.</td>
          </tr>
          <tr>
            <td>30 - 59</td>
            <td><code>Medium</code></td>
            <td>Moderate deviation. Could be a legitimate change in behavior or early sign of compromise.</td>
          </tr>
          <tr>
            <td>0 - 29</td>
            <td><code>Low</code></td>
            <td>Minor deviation. Usually benign but logged for audit purposes.</td>
          </tr>
        </tbody>
      </table>

      <Callout type="info" title="Anomaly Events Are Non-Blocking">
        Anomaly events are always informational — they never block requests. The detector flags
        suspicious behavior so you can investigate, but it does not interrupt user sessions. To
        automatically respond to anomalies, pair anomaly detection with the{' '}
        <a href="/docs/alerting">alerting system</a> to receive notifications when high-severity
        anomalies occur.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  FULL EXAMPLE                                                       */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="full-example">Full Configuration Example</h2>
      <p>
        Below is a complete example that enables anomaly detection alongside other Sentinel features:
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
        // Enable anomaly detection
        Anomaly: sentinel.AnomalyConfig{
            Enabled:        true,
            Sensitivity:    sentinel.AnomalySensitivityMedium,
            LearningPeriod: 7 * 24 * time.Hour,
            Checks: []sentinel.AnomalyCheckType{
                sentinel.CheckOffHoursAccess,
                sentinel.CheckUnusualAccess,
                sentinel.CheckVelocityAnomaly,
                sentinel.CheckImpossibleTravel,
                sentinel.CheckDataExfiltration,
            },
        },

        // Required: tell Sentinel how to identify users
        UserExtractor: func(c *gin.Context) *sentinel.UserContext {
            userID := c.GetHeader("X-User-ID")
            if userID == "" {
                return nil // Unauthenticated request
            }
            return &sentinel.UserContext{
                ID:    userID,
                Email: c.GetHeader("X-User-Email"),
                Role:  c.GetHeader("X-User-Role"),
            }
        },

        // Enable geo for country-based anomaly checks
        Geo: sentinel.GeoConfig{
            Enabled: true,
        },

        // Alert on high-severity anomalies
        Alerts: sentinel.AlertConfig{
            MinSeverity: sentinel.SeverityHigh,
            Webhook: &sentinel.WebhookConfig{
                URL: "https://hooks.example.com/sentinel",
            },
        },
    })

    r.GET("/api/data", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })

    r.Run(":8080")
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  TESTING                                                            */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="testing">Testing Considerations</h2>
      <p>
        Anomaly detection requires sufficient historical data to produce meaningful baselines. This
        makes it harder to test than the WAF or rate limiter, which respond immediately. Here are
        strategies for testing effectively.
      </p>

      <h3>Building a Baseline</h3>
      <p>
        The detector requires at least 10 activity records for a user before it will evaluate
        checks. In a test environment, you can seed activity data by sending authenticated requests
        over a consistent pattern, then introducing an anomalous request to verify detection.
      </p>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Seed baseline activity (repeat over multiple hours/days for a realistic baseline)
for i in $(seq 1 20); do
    curl -s -H "X-User-ID: testuser" http://localhost:8080/api/data > /dev/null
    sleep 1
done

# Now trigger an anomaly — access from a different IP or unusual route
curl -s -H "X-User-ID: testuser" http://localhost:8080/admin/settings
# Check the Sentinel dashboard for an AnomalyDetected event`}
      />

      <h3>Shorter Learning Period for Tests</h3>
      <p>
        Use a short <code>LearningPeriod</code> in test environments so baselines are computed from
        a smaller window of data:
      </p>
      <CodeBlock
        language="go"
        showLineNumbers={false}
        code={`// In tests, use a short learning period
Anomaly: sentinel.AnomalyConfig{
    Enabled:        true,
    Sensitivity:    sentinel.AnomalySensitivityHigh, // Catch everything
    LearningPeriod: 1 * time.Hour,                  // Short window for tests
}`}
      />

      <h3>Unit Testing</h3>
      <p>
        You can test the anomaly detector programmatically by creating a store, seeding activity
        data, and calling <code>CheckActivity</code> directly:
      </p>
      <CodeBlock
        language="go"
        filename="anomaly_test.go"
        code={`func TestAnomalyDetection(t *testing.T) {
    store := memory.New()
    store.Migrate(context.Background())

    pipe := pipeline.New(1000)
    pipe.Start(1)
    defer pipe.Stop()

    geo := intelligence.NewGeoLocator(sentinel.GeoConfig{Enabled: false})

    detector := intelligence.NewAnomalyDetector(store, pipe, geo, sentinel.AnomalyConfig{
        Enabled:        true,
        LearningPeriod: 7 * 24 * time.Hour,
        Sensitivity:    sentinel.AnomalySensitivityMedium,
        Checks: []sentinel.AnomalyCheckType{
            sentinel.CheckOffHoursAccess,
            sentinel.CheckUnusualAccess,
            sentinel.CheckImpossibleTravel,
        },
    })

    // Seed baseline: weekday 9-5 activity from US IP
    for day := 1; day <= 7; day++ {
        for hour := 9; hour <= 17; hour++ {
            ts := time.Now().Add(-time.Duration(day) * 24 * time.Hour)
            store.SaveUserActivity(ctx, &sentinel.UserActivity{
                ID:        fmt.Sprintf("act-%d-%d", day, hour),
                Timestamp: time.Date(ts.Year(), ts.Month(), ts.Day(), hour, 0, 0, 0, ts.Location()),
                UserID:    "user1",
                Path:      "/api/data",
                Method:    "GET",
                IP:        "10.0.0.1",
                Country:   "US",
            })
        }
    }

    // Trigger anomaly: 3am access from a new country
    err := detector.CheckActivity(ctx, &sentinel.UserActivity{
        UserID:    "user1",
        Timestamp: time.Date(2025, 1, 15, 3, 0, 0, 0, time.UTC),
        Path:      "/admin/settings",
        Method:    "GET",
        IP:        "203.0.113.1",
        Country:   "RU",
    })
    if err != nil {
        t.Fatal(err)
    }

    // Verify a ThreatEvent was emitted via the pipeline
    time.Sleep(100 * time.Millisecond)
    // Check pipeline or store for AnomalyDetected event
}`}
      />

      <Callout type="warning" title="Timing in Tests">
        The anomaly detector emits threat events asynchronously through the pipeline. In unit tests,
        add a short <code>time.Sleep</code> (e.g., 100ms) after calling <code>CheckActivity</code>{' '}
        to allow the pipeline to process the event before asserting on results.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  NEXT STEPS                                                         */}
      {/* ------------------------------------------------------------------ */}

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/configuration">Configuration Reference</a> — Full AnomalyConfig field reference</li>
        <li><a href="/docs/auth-shield">Auth Shield</a> — Brute-force and credential stuffing protection</li>
        <li><a href="/docs/waf">WAF</a> — Signature-based attack detection to complement anomaly detection</li>
        <li><a href="/docs/alerting">Alerting</a> — Get notified when anomalies are detected</li>
        <li><a href="/docs/the-dashboard">Dashboard</a> — View anomaly events and user baselines</li>
      </ul>
    </>
  );
}
