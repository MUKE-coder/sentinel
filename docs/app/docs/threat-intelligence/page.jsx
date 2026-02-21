import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';
import { FAQSchema, TechArticleSchema, SpeakableSchema } from '@/components/JsonLd';

export const metadata = {
  title: 'Threat Intelligence - Sentinel Docs',
  description:
    'Automatic threat actor profiling, risk scoring, IP reputation checking, and geolocation in Sentinel for Go applications.',
  alternates: {
    canonical: 'https://sentinel-go-sdk.vercel.app/docs/threat-intelligence',
  },
  openGraph: {
    title: 'Threat Intelligence - Sentinel Docs',
    description:
      'Automatic threat actor profiling, risk scoring, IP reputation checking, and geolocation in Sentinel for Go applications.',
    url: 'https://sentinel-go-sdk.vercel.app/docs/threat-intelligence',
    siteName: 'Sentinel',
    type: 'article',
  },
};

export default function ThreatIntelligence() {
  return (
    <>
      <FAQSchema
        questions={[
          {
            q: 'What is threat actor profiling in Sentinel?',
            a: 'Sentinel automatically creates a persistent profile for every IP that triggers a security event. Each profile tracks first/last seen timestamps, attack types, targeted routes, risk score, geographic origin, and ISP. Profiles are updated incrementally with each new event.',
          },
          {
            q: 'How is the risk score calculated for threat actors?',
            a: 'The risk score ranges from 0 to 100 and is computed from four factors: attack variety (+10 per unique type, max 50), known bad actor flag from AbuseIPDB (+20), recency of last attack within one hour (+10), and high event volume over 100 threats (+20).',
          },
          {
            q: 'How does IP reputation checking work in Sentinel?',
            a: 'When enabled, Sentinel queries the AbuseIPDB API for each attacker IP, retrieves an abuse confidence score, and caches results for 24 hours. You provide your AbuseIPDB API key and set a minimum abuse score threshold for automatic blocking.',
          },
          {
            q: 'Can Sentinel automatically block threat actors?',
            a: 'Yes. Enable AutoBlock in the IPReputationConfig and set a MinAbuseScore threshold (default 80). IPs whose AbuseIPDB confidence score meets or exceeds the threshold are automatically added to the blocklist and rejected by the middleware.',
          },
        ]}
      />
      <TechArticleSchema
        title="Threat Intelligence - Sentinel Docs"
        description="Automatic threat actor profiling, risk scoring, IP reputation checking, and geolocation in Sentinel for Go applications."
        url="https://sentinel-go-sdk.vercel.app/docs/threat-intelligence"
      />
      <SpeakableSchema
        url="https://sentinel-go-sdk.vercel.app/docs/threat-intelligence"
        cssSelector={['h1', 'h2', '.callout']}
      />

      <h1>Threat Intelligence</h1>
      <p>
        Sentinel automatically profiles every IP address that triggers a security event. The Threat
        Intelligence system builds persistent actor profiles, computes risk scores, enriches data
        with geolocation and IP reputation, and provides tools to manage IP blocklists and
        whitelists. All of this happens automatically as events flow through the pipeline — no
        manual configuration is required to start collecting intelligence.
      </p>

      <Callout type="info" title="Automatic Profiling">
        Threat actor profiling is always active when any detection feature is enabled (WAF, Auth
        Shield, Anomaly Detection). Every security event automatically creates or updates the
        corresponding actor profile. You do not need to enable profiling separately.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  THREAT ACTOR PROFILES                                             */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="threat-actor-profiles">Threat Actor Profiles</h2>
      <p>
        Every unique IP address that triggers a security event receives a persistent profile. The
        profiler runs as a pipeline handler, processing each threat event asynchronously and
        updating the corresponding actor record in storage.
      </p>

      <h3>Profile Fields</h3>
      <table>
        <thead>
          <tr>
            <th>Field</th>
            <th>Type</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>IP</code></td>
            <td><code>string</code></td>
            <td>The IP address that uniquely identifies this actor.</td>
          </tr>
          <tr>
            <td><code>FirstSeen</code></td>
            <td><code>time.Time</code></td>
            <td>Timestamp of the first security event from this IP.</td>
          </tr>
          <tr>
            <td><code>LastSeen</code></td>
            <td><code>time.Time</code></td>
            <td>Timestamp of the most recent security event from this IP.</td>
          </tr>
          <tr>
            <td><code>ThreatCount</code></td>
            <td><code>int</code></td>
            <td>Total number of security events attributed to this IP.</td>
          </tr>
          <tr>
            <td><code>AttackTypes</code></td>
            <td><code>[]string</code></td>
            <td>Deduplicated list of attack types observed (e.g., <code>SQLInjection</code>, <code>XSS</code>, <code>BruteForce</code>).</td>
          </tr>
          <tr>
            <td><code>TargetedRoutes</code></td>
            <td><code>[]string</code></td>
            <td>Deduplicated list of routes this actor has targeted (e.g., <code>GET /api/users</code>).</td>
          </tr>
          <tr>
            <td><code>RiskScore</code></td>
            <td><code>int</code></td>
            <td>Computed risk score from 0 to 100. See <a href="#risk-scoring">Risk Scoring</a> below.</td>
          </tr>
          <tr>
            <td><code>Status</code></td>
            <td><code>ActorStatus</code></td>
            <td>Current status: <code>Active</code>, <code>Blocked</code>, or <code>Whitelisted</code>.</td>
          </tr>
          <tr>
            <td><code>Country</code></td>
            <td><code>string</code></td>
            <td>Country of origin (populated by geolocation if enabled).</td>
          </tr>
          <tr>
            <td><code>City</code></td>
            <td><code>string</code></td>
            <td>City of origin (populated by geolocation if enabled).</td>
          </tr>
          <tr>
            <td><code>ISP</code></td>
            <td><code>string</code></td>
            <td>Internet service provider of the IP.</td>
          </tr>
          <tr>
            <td><code>Lat</code> / <code>Lng</code></td>
            <td><code>float64</code></td>
            <td>Geographic coordinates for map visualization in the dashboard.</td>
          </tr>
          <tr>
            <td><code>IsKnownBadActor</code></td>
            <td><code>bool</code></td>
            <td>Set to <code>true</code> if the IP has a high abuse score from IP reputation checking.</td>
          </tr>
          <tr>
            <td><code>AbuseScore</code></td>
            <td><code>int</code></td>
            <td>Abuse confidence score from AbuseIPDB (0-100).</td>
          </tr>
        </tbody>
      </table>

      <p>
        Profiles are created on the first event and updated incrementally on each subsequent event.
        Attack types and targeted routes are deduplicated, so the lists grow only when new distinct
        values appear.
      </p>

      <CodeBlock
        language="go"
        filename="core/models.go"
        code={`// ThreatActor represents a persistent profile of an attacker.
type ThreatActor struct {
    ID              string      \`json:"id"\`
    IP              string      \`json:"ip"\`
    FirstSeen       time.Time   \`json:"first_seen"\`
    LastSeen        time.Time   \`json:"last_seen"\`
    TotalRequests   int         \`json:"total_requests"\`
    ThreatCount     int         \`json:"threat_count"\`
    AttackTypes     []string    \`json:"attack_types"\`
    TargetedRoutes  []string    \`json:"targeted_routes"\`
    RiskScore       int         \`json:"risk_score"\`
    Status          ActorStatus \`json:"status"\`
    Country         string      \`json:"country"\`
    City            string      \`json:"city,omitempty"\`
    ISP             string      \`json:"isp"\`
    IsKnownBadActor bool        \`json:"is_known_bad_actor"\`
    AbuseScore      int         \`json:"abuse_score"\`
    Lat             float64     \`json:"lat"\`
    Lng             float64     \`json:"lng"\`
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  RISK SCORING                                                      */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="risk-scoring">Risk Scoring</h2>
      <p>
        Each threat actor is assigned a risk score between 0 and 100. The score is recomputed every
        time a new threat event is attributed to the actor. The scoring algorithm considers four
        factors:
      </p>

      <table>
        <thead>
          <tr>
            <th>Factor</th>
            <th>Points</th>
            <th>Condition</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Attack Variety</td>
            <td>+10 per unique type (max 50)</td>
            <td>Each distinct attack type in <code>AttackTypes</code> adds 10 points, capped at 50.</td>
          </tr>
          <tr>
            <td>Known Bad Actor</td>
            <td>+20</td>
            <td>IP has been flagged by AbuseIPDB (<code>IsKnownBadActor == true</code>).</td>
          </tr>
          <tr>
            <td>Recency</td>
            <td>+10</td>
            <td>The most recent attack was within the last hour.</td>
          </tr>
          <tr>
            <td>Volume</td>
            <td>+20</td>
            <td>Total threat count exceeds 100 events.</td>
          </tr>
        </tbody>
      </table>

      <p>
        The final score is capped at 100. An actor with 5 unique attack types, a recent attack,
        over 100 events, and a known-bad reputation would score the maximum of 100.
      </p>

      <CodeBlock
        language="go"
        filename="intelligence/profiler.go"
        code={`// ComputeRiskScore calculates a risk score (0-100) for a threat actor.
func ComputeRiskScore(actor *sentinel.ThreatActor) int {
    score := 0

    // +10 for each unique attack type, max 50
    attackTypeScore := len(actor.AttackTypes) * 10
    if attackTypeScore > 50 {
        attackTypeScore = 50
    }
    score += attackTypeScore

    // +20 if known bad actor (AbuseIPDB)
    if actor.IsKnownBadActor {
        score += 20
    }

    // +10 if attacked in last hour
    if time.Since(actor.LastSeen) < time.Hour {
        score += 10
    }

    // +20 if attack count > 100
    if actor.ThreatCount > 100 {
        score += 20
    }

    if score > 100 {
        score = 100
    }
    return score
}`}
      />

      <Callout type="success" title="Risk Score Interpretation">
        <strong>0-20:</strong> Low risk, minimal activity.{' '}
        <strong>21-50:</strong> Moderate risk, multiple attack types or sustained activity.{' '}
        <strong>51-80:</strong> High risk, diverse attack patterns or known bad reputation.{' '}
        <strong>81-100:</strong> Critical risk, consider immediate blocking.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  IP REPUTATION                                                     */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="ip-reputation">IP Reputation</h2>
      <p>
        Sentinel can optionally enrich threat actor profiles with external IP reputation data from{' '}
        <strong>AbuseIPDB</strong>. When enabled, the reputation checker queries the AbuseIPDB API
        for each IP that triggers a security event, retrieves its abuse confidence score, and can
        automatically block IPs that exceed a configurable threshold.
      </p>

      <h3>IPReputationConfig</h3>
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
            <td>Enables IP reputation checking.</td>
          </tr>
          <tr>
            <td><code>AbuseIPDBKey</code></td>
            <td><code>string</code></td>
            <td><code>""</code></td>
            <td>Your AbuseIPDB API key. Required for reputation lookups. Obtain one from <code>abuseipdb.com</code>.</td>
          </tr>
          <tr>
            <td><code>AutoBlock</code></td>
            <td><code>bool</code></td>
            <td><code>false</code></td>
            <td>Automatically block IPs whose abuse score meets or exceeds <code>MinAbuseScore</code>.</td>
          </tr>
          <tr>
            <td><code>MinAbuseScore</code></td>
            <td><code>int</code></td>
            <td><code>80</code></td>
            <td>Minimum AbuseIPDB confidence score (0-100) to trigger auto-blocking.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="main.go"
        code={`sentinel.Mount(r, nil, sentinel.Config{
    IPReputation: sentinel.IPReputationConfig{
        Enabled:       true,
        AbuseIPDBKey:  "your-abuseipdb-api-key",
        AutoBlock:     true,
        MinAbuseScore: 80, // Block IPs with 80%+ abuse confidence
    },
})`}
      />

      <p>
        Reputation results are cached for 24 hours to minimize API calls. The cache is maintained
        in memory and cleared on application restart. When <code>AutoBlock</code> is enabled and an
        IP exceeds the threshold, it is immediately added to the blocklist via the IP Manager.
      </p>

      <Callout type="warning" title="AbuseIPDB Rate Limits">
        The free AbuseIPDB plan allows 1,000 checks per day. If your application processes a high
        volume of unique attacker IPs, consider upgrading your AbuseIPDB plan or increasing{' '}
        <code>MinAbuseScore</code> to reduce the number of reputation lookups triggered by
        low-confidence threats.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  GEOLOCATION                                                       */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="geolocation">Geolocation</h2>
      <p>
        When geolocation is enabled, Sentinel resolves the geographic origin of each attacker IP
        and attaches country, city, coordinates, ISP, and ASN data to both the threat event and
        the actor profile. This data powers the geographic attack map in the dashboard.
      </p>

      <h3>GeoConfig</h3>
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
            <td>Enables IP geolocation lookups.</td>
          </tr>
          <tr>
            <td><code>Provider</code></td>
            <td><code>GeoProvider</code></td>
            <td><code>GeoIPFree</code></td>
            <td>The geolocation provider. Default uses the free <code>ip-api.com</code> service (no API key required).</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="main.go"
        code={`sentinel.Mount(r, nil, sentinel.Config{
    Geo: sentinel.GeoConfig{
        Enabled:  true,
        Provider: sentinel.GeoIPFree, // Free provider, no API key needed
    },
})`}
      />

      <p>
        Geolocation results are cached in an LRU cache (default 10,000 entries) to minimize
        external API calls. Private and loopback IPs (e.g., <code>127.0.0.1</code>,{' '}
        <code>10.x.x.x</code>, <code>192.168.x.x</code>) are skipped automatically.
      </p>

      <h3>GeoResult Fields</h3>
      <table>
        <thead>
          <tr>
            <th>Field</th>
            <th>Type</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>Country</code></td>
            <td><code>string</code></td>
            <td>Full country name (e.g., <code>United States</code>).</td>
          </tr>
          <tr>
            <td><code>CountryCode</code></td>
            <td><code>string</code></td>
            <td>ISO 3166-1 alpha-2 country code (e.g., <code>US</code>).</td>
          </tr>
          <tr>
            <td><code>City</code></td>
            <td><code>string</code></td>
            <td>City name.</td>
          </tr>
          <tr>
            <td><code>Lat</code> / <code>Lng</code></td>
            <td><code>float64</code></td>
            <td>Geographic coordinates.</td>
          </tr>
          <tr>
            <td><code>ISP</code></td>
            <td><code>string</code></td>
            <td>Internet service provider.</td>
          </tr>
          <tr>
            <td><code>ASN</code></td>
            <td><code>string</code></td>
            <td>Autonomous system number and name.</td>
          </tr>
        </tbody>
      </table>

      <Callout type="info" title="Production Geolocation">
        The free <code>ip-api.com</code> provider is rate-limited to 45 requests per minute. For
        production workloads with high traffic, consider using a local MaxMind GeoLite2 database
        for offline lookups with no rate limits.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  IP MANAGEMENT                                                     */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="ip-management">IP Management</h2>
      <p>
        The IP Manager provides a centralized system for blocking and whitelisting IP addresses and
        CIDR ranges. It maintains an in-memory cache that syncs from storage every 30 seconds,
        ensuring fast per-request lookups with no database overhead on the hot path.
      </p>

      <h3>Blocking IPs</h3>
      <p>
        Blocked IPs are rejected by the middleware before reaching your application handlers. You
        can block individual IPs or entire CIDR ranges. Blocks can optionally have an expiration time.
      </p>
      <CodeBlock
        language="go"
        code={`// Block a single IP with no expiration
ipManager.BlockIP(ctx, "203.0.113.50", "Repeated SQL injection attempts", nil)

// Block a CIDR range
ipManager.BlockIP(ctx, "198.51.100.0/24", "Known botnet range", nil)

// Block with expiration (auto-unblock after 24 hours)
expiry := time.Now().Add(24 * time.Hour)
ipManager.BlockIP(ctx, "203.0.113.75", "Temporary block", &expiry)`}
      />

      <h3>Whitelisting IPs</h3>
      <p>
        Whitelisted IPs bypass all security checks including the WAF, rate limiting, and Auth
        Shield. Use this for trusted internal services, monitoring systems, and CI/CD pipelines.
      </p>
      <CodeBlock
        language="go"
        code={`// Whitelist a trusted IP
ipManager.WhitelistIP(ctx, "10.0.0.5")`}
      />

      <h3>How the Cache Works</h3>
      <p>
        The IP Manager loads all blocked and whitelisted IPs into memory at startup. A background
        goroutine re-syncs from storage every 30 seconds to pick up changes made via the API or
        dashboard. Blocking and whitelisting operations update both storage and the in-memory cache
        immediately, so changes take effect without waiting for the next sync cycle.
      </p>

      <Callout type="warning" title="CIDR Matching">
        When you block a CIDR range like <code>198.51.100.0/24</code>, every IP within that range
        is matched. The IP Manager parses CIDR notation and performs subnet containment checks.
        Individual IP blocks use exact string matching for maximum performance.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  FULL CONFIGURATION EXAMPLE                                        */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="full-configuration">Full Configuration Example</h2>
      <p>
        The following example enables all threat intelligence features: profiling, geolocation,
        IP reputation with auto-blocking, and the WAF for event generation.
      </p>
      <CodeBlock
        language="go"
        filename="main.go"
        code={`package main

import (
    sentinel "github.com/MUKE-coder/sentinel"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

    sentinel.Mount(r, nil, sentinel.Config{
        // WAF generates the threat events that feed the profiler
        WAF: sentinel.WAFConfig{
            Enabled: true,
            Mode:    sentinel.ModeBlock,
        },

        // IP reputation enrichment with auto-blocking
        IPReputation: sentinel.IPReputationConfig{
            Enabled:       true,
            AbuseIPDBKey:  "your-abuseipdb-api-key",
            AutoBlock:     true,
            MinAbuseScore: 80,
        },

        // Geolocation for geographic attribution
        Geo: sentinel.GeoConfig{
            Enabled:  true,
            Provider: sentinel.GeoIPFree,
        },
    })

    r.GET("/api/data", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })

    r.Run(":8080")
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  DASHBOARD                                                         */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="dashboard">Dashboard</h2>
      <p>
        The Sentinel dashboard provides two dedicated pages for threat intelligence:
      </p>

      <h3>Actors Page</h3>
      <p>
        The Actors page lists all threat actor profiles with sortable columns for IP, risk score,
        threat count, attack types, country, and last seen time. From this page you can:
      </p>
      <ul>
        <li>Search and filter actors by IP, status, or minimum risk score.</li>
        <li>View the full profile for any actor, including their complete attack history.</li>
        <li>Block an actor directly from their profile with a single click.</li>
        <li>View geographic data and the attack types observed for each actor.</li>
      </ul>

      <h3>IP Management Page</h3>
      <p>
        The IP Management page provides a visual interface for managing your blocklist and
        whitelist:
      </p>
      <ul>
        <li>View all currently blocked IPs and CIDR ranges with block reasons and timestamps.</li>
        <li>Add new IPs or CIDR ranges to the blocklist with an optional expiration.</li>
        <li>Unblock IPs that were previously blocked manually or by auto-blocking.</li>
        <li>Manage the whitelist for trusted IPs.</li>
      </ul>

      <p>
        Access these pages at{' '}
        <code>http://localhost:8080/sentinel/ui</code> and navigate to the Actors or IP Management
        sections.
      </p>

      {/* ------------------------------------------------------------------ */}
      {/*  API REFERENCE                                                     */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="api">API Reference</h2>
      <p>
        All threat intelligence endpoints require authentication via the dashboard JWT token.
        Include the token in the <code>Authorization</code> header as{' '}
        <code>Bearer &lt;token&gt;</code>.
      </p>

      <h3>List Actors</h3>
      <p>
        Returns a paginated list of threat actor profiles with optional filtering.
      </p>
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
            <td><code>GET /sentinel/api/actors</code></td>
          </tr>
          <tr>
            <td>Query Params</td>
            <td>
              <code>status</code>, <code>min_risk</code>, <code>search</code>,{' '}
              <code>page</code>, <code>page_size</code>
            </td>
          </tr>
        </tbody>
      </table>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# List all actors, sorted by default
curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/actors?page=1&page_size=20"

# Filter by minimum risk score
curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/actors?min_risk=50"

# Filter by status
curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/actors?status=Active"`}
      />
      <CodeBlock
        language="json"
        filename="Response"
        showLineNumbers={false}
        code={`{
  "data": [
    {
      "id": "203.0.113.50",
      "ip": "203.0.113.50",
      "first_seen": "2025-01-15T08:23:00Z",
      "last_seen": "2025-01-15T14:45:00Z",
      "total_requests": 347,
      "threat_count": 89,
      "attack_types": ["SQLInjection", "XSS", "PathTraversal"],
      "targeted_routes": ["GET /api/users", "POST /api/search"],
      "risk_score": 70,
      "status": "Active",
      "country": "United States",
      "city": "New York",
      "isp": "Example ISP",
      "is_known_bad_actor": false,
      "abuse_score": 45,
      "lat": 40.7128,
      "lng": -74.006
    }
  ],
  "meta": {
    "total": 42,
    "page": 1,
    "page_size": 20
  }
}`}
      />

      <h3>Get Actor by IP</h3>
      <p>
        Returns the full profile for a specific threat actor.
      </p>
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
            <td><code>GET /sentinel/api/actors/:ip</code></td>
          </tr>
          <tr>
            <td>URL Param</td>
            <td><code>:ip</code> — the IP address of the actor</td>
          </tr>
        </tbody>
      </table>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/actors/203.0.113.50"`}
      />

      <h3>Block Actor</h3>
      <p>
        Blocks a threat actor by IP. The IP is added to the blocklist and all future requests from
        this IP are rejected.
      </p>
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
            <td><code>POST /sentinel/api/actors/:ip/block</code></td>
          </tr>
          <tr>
            <td>URL Param</td>
            <td><code>:ip</code> — the IP address to block</td>
          </tr>
        </tbody>
      </table>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`curl -s -X POST -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/actors/203.0.113.50/block"`}
      />
      <CodeBlock
        language="json"
        filename="Response"
        showLineNumbers={false}
        code={`{
  "message": "Actor blocked"
}`}
      />

      <h3>Actor Request History</h3>
      <p>
        Returns the threat events associated with a specific actor IP.
      </p>
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
            <td><code>GET /sentinel/api/actors/:ip/requests</code></td>
          </tr>
          <tr>
            <td>URL Param</td>
            <td><code>:ip</code> — the IP address of the actor</td>
          </tr>
        </tbody>
      </table>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/actors/203.0.113.50/requests"`}
      />

      <h3>List Blocked IPs</h3>
      <p>
        Returns all currently blocked IPs and CIDR ranges.
      </p>
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
            <td><code>GET /sentinel/api/ip/blocked</code></td>
          </tr>
        </tbody>
      </table>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/ip/blocked"`}
      />
      <CodeBlock
        language="json"
        filename="Response"
        showLineNumbers={false}
        code={`{
  "data": [
    {
      "ip": "203.0.113.50",
      "reason": "Blocked via dashboard",
      "blocked_at": "2025-01-15T14:50:00Z",
      "expires_at": null,
      "cidr": false
    },
    {
      "ip": "198.51.100.0/24",
      "reason": "Known botnet range",
      "blocked_at": "2025-01-14T09:00:00Z",
      "expires_at": null,
      "cidr": true
    }
  ]
}`}
      />

      <h3>Block IP</h3>
      <p>
        Adds an IP or CIDR range to the blocklist.
      </p>
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
            <td><code>POST /sentinel/api/ip/block</code></td>
          </tr>
          <tr>
            <td>Body</td>
            <td>JSON with <code>ip</code> (required), <code>reason</code>, <code>expiry</code> (optional, RFC3339)</td>
          </tr>
        </tbody>
      </table>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Block a single IP
curl -s -X POST -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json" \\
  -d '{"ip": "203.0.113.75", "reason": "Manual block"}' \\
  "http://localhost:8080/sentinel/api/ip/block"

# Block a CIDR range with expiration
curl -s -X POST -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json" \\
  -d '{"ip": "198.51.100.0/24", "reason": "Temporary block", "expiry": "2025-02-15T00:00:00Z"}' \\
  "http://localhost:8080/sentinel/api/ip/block"`}
      />

      <h3>Unblock IP</h3>
      <p>
        Removes an IP or CIDR range from the blocklist. For CIDR ranges, replace <code>/</code>{' '}
        with <code>_</code> in the URL parameter (e.g., <code>198.51.100.0_24</code>).
      </p>
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
            <td><code>DELETE /sentinel/api/ip/block/:ip</code></td>
          </tr>
          <tr>
            <td>URL Param</td>
            <td><code>:ip</code> — the IP or CIDR (with <code>/</code> replaced by <code>_</code>)</td>
          </tr>
        </tbody>
      </table>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Unblock a single IP
curl -s -X DELETE -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/ip/block/203.0.113.75"

# Unblock a CIDR range (replace / with _)
curl -s -X DELETE -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/ip/block/198.51.100.0_24"`}
      />

      <h3>IP Reputation Lookup</h3>
      <p>
        Retrieves the AbuseIPDB reputation data for a specific IP (requires IP reputation to be
        enabled).
      </p>
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
            <td><code>GET /sentinel/api/ip/:ip/reputation</code></td>
          </tr>
        </tbody>
      </table>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/ip/203.0.113.50/reputation"`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  TESTING                                                           */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="testing">Testing</h2>
      <p>
        After enabling the WAF or any other detection feature, threat actor profiles are created
        automatically. You can verify the intelligence system is working by triggering a few test
        events and then querying the actors API.
      </p>

      <h3>Step 1: Trigger Security Events</h3>
      <p>
        Send a few malicious requests to generate threat events. These will automatically create
        actor profiles.
      </p>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Trigger a SQL injection event
curl -s "http://localhost:8080/api/data?id=1'+OR+'1'='1"

# Trigger an XSS event
curl -s "http://localhost:8080/api/data?q=<script>alert(1)</script>"

# Trigger a path traversal event
curl -s "http://localhost:8080/api/data/../../../../etc/passwd"`}
      />

      <h3>Step 2: Log In to the Dashboard API</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Obtain a JWT token
TOKEN=$(curl -s -X POST http://localhost:8080/sentinel/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username":"admin","password":"sentinel"}' | jq -r '.token')

echo $TOKEN`}
      />

      <h3>Step 3: View Actor Profiles</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# List all actors
curl -s -H "Authorization: Bearer $TOKEN" \\
  "http://localhost:8080/sentinel/api/actors" | jq .

# View a specific actor (use your test IP, likely 127.0.0.1)
curl -s -H "Authorization: Bearer $TOKEN" \\
  "http://localhost:8080/sentinel/api/actors/127.0.0.1" | jq .

# View the threat history for an actor
curl -s -H "Authorization: Bearer $TOKEN" \\
  "http://localhost:8080/sentinel/api/actors/127.0.0.1/requests" | jq .`}
      />

      <h3>Step 4: Test IP Blocking</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Block an actor
curl -s -X POST -H "Authorization: Bearer $TOKEN" \\
  "http://localhost:8080/sentinel/api/actors/203.0.113.50/block" | jq .

# Verify the IP appears in the blocklist
curl -s -H "Authorization: Bearer $TOKEN" \\
  "http://localhost:8080/sentinel/api/ip/blocked" | jq .

# Unblock the IP
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" \\
  "http://localhost:8080/sentinel/api/ip/block/203.0.113.50" | jq .`}
      />

      <Callout type="danger" title="Local Testing Note">
        When testing locally, all requests originate from <code>127.0.0.1</code> or{' '}
        <code>::1</code>, so all test events will be attributed to a single actor profile.
        Geolocation lookups are skipped for private and loopback IPs. To test with realistic
        geographic data, deploy to a staging environment and send requests from external IPs.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  NEXT STEPS                                                        */}
      {/* ------------------------------------------------------------------ */}

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/waf">WAF</a> — Configure the WAF rules that generate threat events</li>
        <li><a href="/docs/auth-shield">Auth Shield</a> — Protect login endpoints from brute-force attacks</li>
        <li><a href="/docs/anomaly-detection">Anomaly Detection</a> — Add behavioral analysis for advanced threat detection</li>
        <li><a href="/docs/alerting">Alerting</a> — Get notified when high-risk actors are detected</li>
        <li><a href="/docs/the-dashboard">Dashboard</a> — Explore the Actors and IP Management pages</li>
      </ul>
    </>
  );
}
