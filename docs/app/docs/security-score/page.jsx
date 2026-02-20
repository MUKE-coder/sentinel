import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';

export const metadata = { title: 'Security Score - Sentinel Docs' };

export default function SecurityScore() {
  return (
    <>
      <h1>Security Score</h1>
      <p>
        The Security Score is a weighted composite metric (0-100) that measures your application's
        overall security posture at a glance. It aggregates five dimensions of your Sentinel
        configuration and runtime behavior into a single number, graded from <strong>A</strong> (90-100)
        to <strong>F</strong> (below 60). The score updates automatically in the background and
        surfaces actionable recommendations to improve your defenses.
      </p>

      <Callout type="info" title="Always Active">
        The score engine runs automatically once Sentinel is mounted. There is no separate
        configuration to enable it. It uses the main <code>Config</code> you pass to{' '}
        <code>sentinel.Mount</code> to evaluate which features are active and how well they are
        configured.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  FIVE DIMENSIONS                                                   */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="dimensions">Score Dimensions</h2>
      <p>
        The overall score is a weighted sum of five sub-scores. Each dimension evaluates a different
        aspect of your security posture:
      </p>

      <table>
        <thead>
          <tr>
            <th>Dimension</th>
            <th>Weight</th>
            <th>What It Measures</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>Threat Activity</strong></td>
            <td>30%</td>
            <td>
              How many threats were detected in the last 24 hours and how severe they are. Fewer and
              lower-severity threats yield a higher score. A bonus is applied when your block rate
              exceeds 90%.
            </td>
          </tr>
          <tr>
            <td><strong>Auth Security</strong></td>
            <td>20%</td>
            <td>
              Whether you have changed the default dashboard password and secret key, and whether Auth
              Shield is enabled. Using defaults penalizes this sub-score.
            </td>
          </tr>
          <tr>
            <td><strong>Response Posture</strong></td>
            <td>20%</td>
            <td>
              The ratio of blocked threats to total threats. A 100% block rate yields a perfect
              sub-score. If the WAF is in log-only mode, unblocked threats lower this dimension.
            </td>
          </tr>
          <tr>
            <td><strong>Header Compliance</strong></td>
            <td>15%</td>
            <td>
              How many recommended security headers are configured: <code>X-Frame-Options</code>,{' '}
              <code>Referrer-Policy</code>, <code>Content-Security-Policy</code>, and{' '}
              <code>Strict-Transport-Security</code>. <code>X-Content-Type-Options</code> is always
              set by default.
            </td>
          </tr>
          <tr>
            <td><strong>Rate Limiting</strong></td>
            <td>15%</td>
            <td>
              Whether rate limiting is enabled and how comprehensively it is configured: per-IP,
              per-user, and per-route limits each contribute to this sub-score.
            </td>
          </tr>
        </tbody>
      </table>

      {/* ------------------------------------------------------------------ */}
      {/*  HOW IT'S COMPUTED                                                 */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="how-it-works">How It's Computed</h2>
      <p>
        Sentinel launches a background goroutine when <code>Mount</code> is called. The{' '}
        <code>ScoreEngine</code> computes the score immediately on startup and then recomputes it
        every 5 minutes. Each cycle performs the following steps:
      </p>
      <ol>
        <li>
          <strong>Query threat stats</strong> — The engine calls <code>GetThreatStats</code> on the
          storage layer with a 24-hour window to retrieve counts by severity and block status.
        </li>
        <li>
          <strong>Evaluate each dimension</strong> — Five dedicated functions compute a sub-score
          (0-100) for each dimension using the threat stats and the current <code>Config</code>.
        </li>
        <li>
          <strong>Weighted aggregation</strong> — Sub-scores are multiplied by their weights and
          summed to produce the overall score.
        </li>
        <li>
          <strong>Grade assignment</strong> — The overall score is mapped to a letter grade.
        </li>
        <li>
          <strong>Recommendation generation</strong> — The engine inspects each sub-score and the
          config to produce actionable recommendations for any weak areas.
        </li>
        <li>
          <strong>Persist</strong> — The result is saved to storage via{' '}
          <code>SaveSecurityScore</code> so the dashboard and API can read it without recomputing.
        </li>
      </ol>

      <CodeBlock
        language="go"
        filename="intelligence/security_score.go"
        code={`// ComputeScore calculates the security score based on current state.
func (e *ScoreEngine) ComputeScore(ctx context.Context) (*sentinel.SecurityScore, error) {
    stats, err := e.store.GetThreatStats(ctx, 24*time.Hour)
    if err != nil {
        return nil, err
    }

    threatScore   := computeThreatActivityScore(stats)    // weight: 30%
    authScore     := computeAuthSecurityScore(e.config)   // weight: 20%
    responseScore := computeResponsePostureScore(stats)   // weight: 20%
    headerScore   := computeHeaderComplianceScore(e.config) // weight: 15%
    rateLimitScore := computeRateLimitCoverageScore(e.config) // weight: 15%

    overall := int(
        float64(threatScore)*0.30 +
        float64(authScore)*0.20 +
        float64(responseScore)*0.20 +
        float64(headerScore)*0.15 +
        float64(rateLimitScore)*0.15,
    )

    grade := scoreToGrade(overall)
    recommendations := generateRecommendations(
        threatScore, authScore, responseScore,
        headerScore, rateLimitScore, e.config,
    )

    score := &sentinel.SecurityScore{
        Overall: overall,
        Grade:   grade,
        // ... sub-scores, computed_at, recommendations
    }

    e.store.SaveSecurityScore(ctx, score)
    return score, nil
}`}
      />

      <h3>Grading Scale</h3>
      <table>
        <thead>
          <tr>
            <th>Score Range</th>
            <th>Grade</th>
            <th>Interpretation</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>90 - 100</td>
            <td><strong>A</strong></td>
            <td>Excellent. All major features enabled and well-configured.</td>
          </tr>
          <tr>
            <td>80 - 89</td>
            <td><strong>B</strong></td>
            <td>Good. Minor improvements available.</td>
          </tr>
          <tr>
            <td>70 - 79</td>
            <td><strong>C</strong></td>
            <td>Fair. Some important features are missing or misconfigured.</td>
          </tr>
          <tr>
            <td>60 - 69</td>
            <td><strong>D</strong></td>
            <td>Poor. Significant gaps in your security posture.</td>
          </tr>
          <tr>
            <td>0 - 59</td>
            <td><strong>F</strong></td>
            <td>Failing. Critical features are disabled or defaults are unchanged.</td>
          </tr>
        </tbody>
      </table>

      {/* ------------------------------------------------------------------ */}
      {/*  SUB-SCORE DETAILS                                                 */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="sub-score-details">Sub-Score Details</h2>

      <h3>Threat Activity (30%)</h3>
      <p>
        Starts at 100 and deducts points for each threat detected in the last 24 hours. Deductions
        scale by severity: critical threats cost 20 points each, high costs 10, medium costs 5, and
        low costs 2. A bonus of +10 is applied when over 90% of threats are blocked, or +5 when over
        50% are blocked. With no threats in the window, the sub-score is a perfect 100.
      </p>

      <h3>Auth Security (20%)</h3>
      <p>
        Starts at a base of 50. Changing the default dashboard password from{' '}
        <code>"sentinel"</code> adds 20 points. Changing the default secret key adds another 20.
        Enabling Auth Shield adds 10. A fully configured authentication setup scores 100.
      </p>

      <h3>Response Posture (20%)</h3>
      <p>
        Measures the percentage of threats that were actively blocked. If all detected threats are
        blocked (WAF in block mode), the sub-score is 100. If no threats have been detected, the
        baseline score is 80. Running the WAF in log-only mode typically lowers this dimension because
        threats are recorded but not blocked.
      </p>

      <h3>Header Compliance (15%)</h3>
      <p>
        Counts how many of the five recommended security headers are configured:{' '}
        <code>X-Content-Type-Options</code> (always on), <code>X-Frame-Options</code>,{' '}
        <code>Referrer-Policy</code>, <code>Content-Security-Policy</code>, and{' '}
        <code>Strict-Transport-Security</code>. Each configured header contributes equally. If
        security headers are explicitly disabled, the sub-score is 0.
      </p>

      <h3>Rate Limiting (15%)</h3>
      <p>
        Awards a base of 30 points for having rate limiting enabled. Additional points come from
        configuring per-IP limits (+30), per-user limits (+20), and per-route limits (+20).
        Disabling rate limiting entirely results in a sub-score of 0.
      </p>

      <Callout type="success" title="Maximizing Your Score">
        To reach an A grade: enable WAF in block mode, enable rate limiting with per-IP and per-user
        limits, configure all five security headers, change the default dashboard password and secret
        key, and enable Auth Shield. These settings cover all five dimensions.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  RECOMMENDATIONS                                                   */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="recommendations">Recommendations</h2>
      <p>
        After computing the score, the engine generates a list of actionable recommendations based on
        which features are disabled or which sub-scores fall below their thresholds. Each
        recommendation includes a title, description, impact level, and the category it addresses.
      </p>

      <table>
        <thead>
          <tr>
            <th>Condition</th>
            <th>Recommendation</th>
            <th>Impact</th>
            <th>Category</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>WAF disabled</td>
            <td>Enable WAF to protect against common attacks</td>
            <td>High</td>
            <td><code>threat_activity</code></td>
          </tr>
          <tr>
            <td>WAF in log-only mode</td>
            <td>Set WAF to block mode to actively prevent attacks</td>
            <td>High</td>
            <td><code>response_posture</code></td>
          </tr>
          <tr>
            <td>Rate limiting disabled</td>
            <td>Enable rate limiting to prevent abuse and brute force</td>
            <td>Medium</td>
            <td><code>rate_limit_coverage</code></td>
          </tr>
          <tr>
            <td>Header compliance below 80</td>
            <td>Configure CSP and HSTS headers</td>
            <td>Medium</td>
            <td><code>header_compliance</code></td>
          </tr>
          <tr>
            <td>Auth security below 70</td>
            <td>Change default passwords and enable Auth Shield</td>
            <td>High</td>
            <td><code>auth_security</code></td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="intelligence/security_score.go"
        showLineNumbers={false}
        code={`// Example recommendation structure
type Recommendation struct {
    Title       string \`json:"title"\`
    Description string \`json:"description"\`
    Impact      string \`json:"impact"\`       // "High", "Medium", "Low"
    Category    string \`json:"category"\`      // matches a sub-score dimension
}`}
      />

      <Callout type="warning" title="Act on Recommendations">
        Recommendations are not just informational. Each one directly maps to a sub-score dimension.
        Implementing a high-impact recommendation can raise your overall score by 10-20 points.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  API                                                               */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="api">API</h2>
      <p>
        The security score is available through a single authenticated endpoint. The response includes
        the overall score, grade, each sub-score with its weight and label, the computation timestamp,
        trend direction, and the list of recommendations.
      </p>

      <h3>Get Security Score</h3>
      <table>
        <thead>
          <tr>
            <th>Property</th>
            <th>Value</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Endpoint</td>
            <td><code>GET /sentinel/api/score</code></td>
          </tr>
          <tr>
            <td>Auth</td>
            <td>JWT token in <code>Authorization: Bearer &lt;token&gt;</code></td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/score" | jq .`}
      />

      <CodeBlock
        language="json"
        filename="Response"
        showLineNumbers={false}
        code={`{
  "data": {
    "overall": 82,
    "grade": "B",
    "threat_activity": {
      "score": 90,
      "weight": 0.3,
      "label": "Threat Activity"
    },
    "auth_security": {
      "score": 80,
      "weight": 0.2,
      "label": "Auth Security"
    },
    "response_posture": {
      "score": 100,
      "weight": 0.2,
      "label": "Response Posture"
    },
    "header_compliance": {
      "score": 60,
      "weight": 0.15,
      "label": "Header Compliance"
    },
    "rate_limit_coverage": {
      "score": 50,
      "weight": 0.15,
      "label": "Rate Limiting"
    },
    "computed_at": "2025-01-15T14:30:00Z",
    "trend": "stable",
    "recommendations": [
      {
        "title": "Add Security Headers",
        "description": "Configure Content-Security-Policy and Strict-Transport-Security headers.",
        "impact": "Medium",
        "category": "header_compliance"
      },
      {
        "title": "Enable Rate Limiting",
        "description": "Enable rate limiting to prevent abuse and brute force attacks.",
        "impact": "Medium",
        "category": "rate_limit_coverage"
      }
    ]
  }
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  DASHBOARD                                                         */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="dashboard">Dashboard</h2>
      <p>
        The security score is surfaced in two places within the Sentinel dashboard:
      </p>
      <ul>
        <li>
          <strong>Main Dashboard</strong> — The home page displays the overall score as a ring gauge
          with the letter grade at the center. The gauge color shifts from red (F) through amber (C/D)
          to green (A/B), providing an instant visual indicator of your security posture.
        </li>
        <li>
          <strong>Analytics Page</strong> — The analytics section shows a detailed score breakdown
          with each sub-score displayed individually. This view lets you identify which specific
          dimension is dragging down your overall score and view the associated recommendations.
        </li>
      </ul>
      <p>
        Access the dashboard at <code>http://localhost:8080/sentinel/ui</code> after mounting
        Sentinel.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  CONFIGURATION                                                     */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="configuration">Configuration</h2>
      <p>
        The score engine does not have its own configuration block. It reads the main{' '}
        <code>Config</code> you pass to <code>sentinel.Mount</code> to determine which features are
        enabled and how they are configured. The sub-scores react directly to your config:
      </p>

      <table>
        <thead>
          <tr>
            <th>Config Area</th>
            <th>Affects Dimension</th>
            <th>What the Engine Checks</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>WAF</code></td>
            <td>Threat Activity, Response Posture</td>
            <td>Whether WAF is enabled and whether it is in block or log mode.</td>
          </tr>
          <tr>
            <td><code>RateLimit</code></td>
            <td>Rate Limiting</td>
            <td>Whether rate limiting is enabled and which limit types are configured (by-IP, by-user, by-route).</td>
          </tr>
          <tr>
            <td><code>Headers</code></td>
            <td>Header Compliance</td>
            <td>Which security headers are explicitly set in the config.</td>
          </tr>
          <tr>
            <td><code>Dashboard</code></td>
            <td>Auth Security</td>
            <td>Whether the password and secret key have been changed from their defaults.</td>
          </tr>
          <tr>
            <td><code>AuthShield</code></td>
            <td>Auth Security</td>
            <td>Whether Auth Shield brute-force protection is enabled.</td>
          </tr>
        </tbody>
      </table>

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

    // A well-configured setup that achieves a high security score
    sentinel.Mount(r, nil, sentinel.Config{
        // WAF in block mode -> high Threat Activity & Response Posture
        WAF: sentinel.WAFConfig{
            Enabled: true,
            Mode:    sentinel.ModeBlock,
        },

        // Rate limiting with per-IP and per-user -> high Rate Limiting
        RateLimit: sentinel.RateLimitConfig{
            Enabled: true,
            ByIP:    &sentinel.Limit{Requests: 100, Window: time.Minute},
            ByUser:  &sentinel.Limit{Requests: 200, Window: time.Minute},
            ByRoute: map[string]sentinel.Limit{
                "/api/login": {Requests: 5, Window: 15 * time.Minute},
            },
        },

        // Full security headers -> high Header Compliance
        Headers: sentinel.HeadersConfig{
            XFrameOptions:            "DENY",
            ReferrerPolicy:           "strict-origin-when-cross-origin",
            ContentSecurityPolicy:    "default-src 'self'",
            StrictTransportSecurity:  true,
        },

        // Custom credentials -> high Auth Security
        Dashboard: sentinel.DashboardConfig{
            Password:  "my-strong-password",
            SecretKey: "my-custom-jwt-secret-key",
        },

        // Auth Shield enabled -> bonus Auth Security points
        AuthShield: sentinel.AuthShieldConfig{
            Enabled:         true,
            MaxAttempts:     5,
            LockoutDuration: 15 * time.Minute,
        },
    })

    r.GET("/api/data", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })

    r.Run(":8080")
}`}
      />

      <Callout type="info" title="Background Recomputation">
        The score engine runs in a background goroutine that ticks every 5 minutes. It also computes
        the score once immediately on startup. The API endpoint{' '}
        <code>GET /sentinel/api/score</code> triggers a fresh computation on each request, so you
        always get the latest result. The background goroutine ensures the persisted score stays
        current for the dashboard even when the API is not being called.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  NEXT STEPS                                                        */}
      {/* ------------------------------------------------------------------ */}

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/configuration">Configuration Reference</a> — Full config field reference for all features that affect the score</li>
        <li><a href="/docs/waf">WAF</a> — Enable and configure the WAF to improve Threat Activity and Response Posture</li>
        <li><a href="/docs/rate-limiting">Rate Limiting</a> — Configure rate limits to boost the Rate Limiting dimension</li>
        <li><a href="/docs/security-headers">Security Headers</a> — Add headers to maximize Header Compliance</li>
        <li><a href="/docs/auth-shield">Auth Shield</a> — Enable brute-force protection to raise Auth Security</li>
      </ul>
    </>
  );
}
