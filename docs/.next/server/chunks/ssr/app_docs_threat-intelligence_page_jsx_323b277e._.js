module.exports=[45981,a=>{"use strict";var b=a.i(81332),c=a.i(17924),d=a.i(64939);function e(){return(0,b.jsxs)(b.Fragment,{children:[(0,b.jsx)("h1",{children:"Threat Intelligence"}),(0,b.jsx)("p",{children:"Sentinel automatically profiles every IP address that triggers a security event. The Threat Intelligence system builds persistent actor profiles, computes risk scores, enriches data with geolocation and IP reputation, and provides tools to manage IP blocklists and whitelists. All of this happens automatically as events flow through the pipeline — no manual configuration is required to start collecting intelligence."}),(0,b.jsx)(d.default,{type:"info",title:"Automatic Profiling",children:"Threat actor profiling is always active when any detection feature is enabled (WAF, Auth Shield, Anomaly Detection). Every security event automatically creates or updates the corresponding actor profile. You do not need to enable profiling separately."}),(0,b.jsx)("h2",{id:"threat-actor-profiles",children:"Threat Actor Profiles"}),(0,b.jsx)("p",{children:"Every unique IP address that triggers a security event receives a persistent profile. The profiler runs as a pipeline handler, processing each threat event asynchronously and updating the corresponding actor record in storage."}),(0,b.jsx)("h3",{children:"Profile Fields"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"IP"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"The IP address that uniquely identifies this actor."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"FirstSeen"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"time.Time"})}),(0,b.jsx)("td",{children:"Timestamp of the first security event from this IP."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"LastSeen"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"time.Time"})}),(0,b.jsx)("td",{children:"Timestamp of the most recent security event from this IP."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ThreatCount"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"int"})}),(0,b.jsx)("td",{children:"Total number of security events attributed to this IP."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"AttackTypes"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"[]string"})}),(0,b.jsxs)("td",{children:["Deduplicated list of attack types observed (e.g., ",(0,b.jsx)("code",{children:"SQLInjection"}),", ",(0,b.jsx)("code",{children:"XSS"}),", ",(0,b.jsx)("code",{children:"BruteForce"}),")."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"TargetedRoutes"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"[]string"})}),(0,b.jsxs)("td",{children:["Deduplicated list of routes this actor has targeted (e.g., ",(0,b.jsx)("code",{children:"GET /api/users"}),")."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RiskScore"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"int"})}),(0,b.jsxs)("td",{children:["Computed risk score from 0 to 100. See ",(0,b.jsx)("a",{href:"#risk-scoring",children:"Risk Scoring"})," below."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Status"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ActorStatus"})}),(0,b.jsxs)("td",{children:["Current status: ",(0,b.jsx)("code",{children:"Active"}),", ",(0,b.jsx)("code",{children:"Blocked"}),", or ",(0,b.jsx)("code",{children:"Whitelisted"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Country"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Country of origin (populated by geolocation if enabled)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"City"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"City of origin (populated by geolocation if enabled)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ISP"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Internet service provider of the IP."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsxs)("td",{children:[(0,b.jsx)("code",{children:"Lat"})," / ",(0,b.jsx)("code",{children:"Lng"})]}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"float64"})}),(0,b.jsx)("td",{children:"Geographic coordinates for map visualization in the dashboard."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"IsKnownBadActor"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsxs)("td",{children:["Set to ",(0,b.jsx)("code",{children:"true"})," if the IP has a high abuse score from IP reputation checking."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"AbuseScore"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"int"})}),(0,b.jsx)("td",{children:"Abuse confidence score from AbuseIPDB (0-100)."})]})]})]}),(0,b.jsx)("p",{children:"Profiles are created on the first event and updated incrementally on each subsequent event. Attack types and targeted routes are deduplicated, so the lists grow only when new distinct values appear."}),(0,b.jsx)(c.default,{language:"go",filename:"core/models.go",code:`// ThreatActor represents a persistent profile of an attacker.
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
}`}),(0,b.jsx)("h2",{id:"risk-scoring",children:"Risk Scoring"}),(0,b.jsx)("p",{children:"Each threat actor is assigned a risk score between 0 and 100. The score is recomputed every time a new threat event is attributed to the actor. The scoring algorithm considers four factors:"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Factor"}),(0,b.jsx)("th",{children:"Points"}),(0,b.jsx)("th",{children:"Condition"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Attack Variety"}),(0,b.jsx)("td",{children:"+10 per unique type (max 50)"}),(0,b.jsxs)("td",{children:["Each distinct attack type in ",(0,b.jsx)("code",{children:"AttackTypes"})," adds 10 points, capped at 50."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Known Bad Actor"}),(0,b.jsx)("td",{children:"+20"}),(0,b.jsxs)("td",{children:["IP has been flagged by AbuseIPDB (",(0,b.jsx)("code",{children:"IsKnownBadActor == true"}),")."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Recency"}),(0,b.jsx)("td",{children:"+10"}),(0,b.jsx)("td",{children:"The most recent attack was within the last hour."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Volume"}),(0,b.jsx)("td",{children:"+20"}),(0,b.jsx)("td",{children:"Total threat count exceeds 100 events."})]})]})]}),(0,b.jsx)("p",{children:"The final score is capped at 100. An actor with 5 unique attack types, a recent attack, over 100 events, and a known-bad reputation would score the maximum of 100."}),(0,b.jsx)(c.default,{language:"go",filename:"intelligence/profiler.go",code:`// ComputeRiskScore calculates a risk score (0-100) for a threat actor.
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
}`}),(0,b.jsxs)(d.default,{type:"success",title:"Risk Score Interpretation",children:[(0,b.jsx)("strong",{children:"0-20:"})," Low risk, minimal activity."," ",(0,b.jsx)("strong",{children:"21-50:"})," Moderate risk, multiple attack types or sustained activity."," ",(0,b.jsx)("strong",{children:"51-80:"})," High risk, diverse attack patterns or known bad reputation."," ",(0,b.jsx)("strong",{children:"81-100:"})," Critical risk, consider immediate blocking."]}),(0,b.jsx)("h2",{id:"ip-reputation",children:"IP Reputation"}),(0,b.jsxs)("p",{children:["Sentinel can optionally enrich threat actor profiles with external IP reputation data from"," ",(0,b.jsx)("strong",{children:"AbuseIPDB"}),". When enabled, the reputation checker queries the AbuseIPDB API for each IP that triggers a security event, retrieves its abuse confidence score, and can automatically block IPs that exceed a configurable threshold."]}),(0,b.jsx)("h3",{children:"IPReputationConfig"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsx)("td",{children:"Enables IP reputation checking."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"AbuseIPDBKey"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:'""'})}),(0,b.jsxs)("td",{children:["Your AbuseIPDB API key. Required for reputation lookups. Obtain one from ",(0,b.jsx)("code",{children:"abuseipdb.com"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"AutoBlock"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsxs)("td",{children:["Automatically block IPs whose abuse score meets or exceeds ",(0,b.jsx)("code",{children:"MinAbuseScore"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"MinAbuseScore"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"int"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"80"})}),(0,b.jsx)("td",{children:"Minimum AbuseIPDB confidence score (0-100) to trigger auto-blocking."})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`sentinel.Mount(r, nil, sentinel.Config{
    IPReputation: sentinel.IPReputationConfig{
        Enabled:       true,
        AbuseIPDBKey:  "your-abuseipdb-api-key",
        AutoBlock:     true,
        MinAbuseScore: 80, // Block IPs with 80%+ abuse confidence
    },
})`}),(0,b.jsxs)("p",{children:["Reputation results are cached for 24 hours to minimize API calls. The cache is maintained in memory and cleared on application restart. When ",(0,b.jsx)("code",{children:"AutoBlock"})," is enabled and an IP exceeds the threshold, it is immediately added to the blocklist via the IP Manager."]}),(0,b.jsxs)(d.default,{type:"warning",title:"AbuseIPDB Rate Limits",children:["The free AbuseIPDB plan allows 1,000 checks per day. If your application processes a high volume of unique attacker IPs, consider upgrading your AbuseIPDB plan or increasing"," ",(0,b.jsx)("code",{children:"MinAbuseScore"})," to reduce the number of reputation lookups triggered by low-confidence threats."]}),(0,b.jsx)("h2",{id:"geolocation",children:"Geolocation"}),(0,b.jsx)("p",{children:"When geolocation is enabled, Sentinel resolves the geographic origin of each attacker IP and attaches country, city, coordinates, ISP, and ASN data to both the threat event and the actor profile. This data powers the geographic attack map in the dashboard."}),(0,b.jsx)("h3",{children:"GeoConfig"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsx)("td",{children:"Enables IP geolocation lookups."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Provider"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"GeoProvider"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"GeoIPFree"})}),(0,b.jsxs)("td",{children:["The geolocation provider. Default uses the free ",(0,b.jsx)("code",{children:"ip-api.com"})," service (no API key required)."]})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`sentinel.Mount(r, nil, sentinel.Config{
    Geo: sentinel.GeoConfig{
        Enabled:  true,
        Provider: sentinel.GeoIPFree, // Free provider, no API key needed
    },
})`}),(0,b.jsxs)("p",{children:["Geolocation results are cached in an LRU cache (default 10,000 entries) to minimize external API calls. Private and loopback IPs (e.g., ",(0,b.jsx)("code",{children:"127.0.0.1"}),","," ",(0,b.jsx)("code",{children:"10.x.x.x"}),", ",(0,b.jsx)("code",{children:"192.168.x.x"}),") are skipped automatically."]}),(0,b.jsx)("h3",{children:"GeoResult Fields"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Country"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsxs)("td",{children:["Full country name (e.g., ",(0,b.jsx)("code",{children:"United States"}),")."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CountryCode"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsxs)("td",{children:["ISO 3166-1 alpha-2 country code (e.g., ",(0,b.jsx)("code",{children:"US"}),")."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"City"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"City name."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsxs)("td",{children:[(0,b.jsx)("code",{children:"Lat"})," / ",(0,b.jsx)("code",{children:"Lng"})]}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"float64"})}),(0,b.jsx)("td",{children:"Geographic coordinates."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ISP"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Internet service provider."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ASN"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Autonomous system number and name."})]})]})]}),(0,b.jsxs)(d.default,{type:"info",title:"Production Geolocation",children:["The free ",(0,b.jsx)("code",{children:"ip-api.com"})," provider is rate-limited to 45 requests per minute. For production workloads with high traffic, consider using a local MaxMind GeoLite2 database for offline lookups with no rate limits."]}),(0,b.jsx)("h2",{id:"ip-management",children:"IP Management"}),(0,b.jsx)("p",{children:"The IP Manager provides a centralized system for blocking and whitelisting IP addresses and CIDR ranges. It maintains an in-memory cache that syncs from storage every 30 seconds, ensuring fast per-request lookups with no database overhead on the hot path."}),(0,b.jsx)("h3",{children:"Blocking IPs"}),(0,b.jsx)("p",{children:"Blocked IPs are rejected by the middleware before reaching your application handlers. You can block individual IPs or entire CIDR ranges. Blocks can optionally have an expiration time."}),(0,b.jsx)(c.default,{language:"go",code:`// Block a single IP with no expiration
ipManager.BlockIP(ctx, "203.0.113.50", "Repeated SQL injection attempts", nil)

// Block a CIDR range
ipManager.BlockIP(ctx, "198.51.100.0/24", "Known botnet range", nil)

// Block with expiration (auto-unblock after 24 hours)
expiry := time.Now().Add(24 * time.Hour)
ipManager.BlockIP(ctx, "203.0.113.75", "Temporary block", &expiry)`}),(0,b.jsx)("h3",{children:"Whitelisting IPs"}),(0,b.jsx)("p",{children:"Whitelisted IPs bypass all security checks including the WAF, rate limiting, and Auth Shield. Use this for trusted internal services, monitoring systems, and CI/CD pipelines."}),(0,b.jsx)(c.default,{language:"go",code:`// Whitelist a trusted IP
ipManager.WhitelistIP(ctx, "10.0.0.5")`}),(0,b.jsx)("h3",{children:"How the Cache Works"}),(0,b.jsx)("p",{children:"The IP Manager loads all blocked and whitelisted IPs into memory at startup. A background goroutine re-syncs from storage every 30 seconds to pick up changes made via the API or dashboard. Blocking and whitelisting operations update both storage and the in-memory cache immediately, so changes take effect without waiting for the next sync cycle."}),(0,b.jsxs)(d.default,{type:"warning",title:"CIDR Matching",children:["When you block a CIDR range like ",(0,b.jsx)("code",{children:"198.51.100.0/24"}),", every IP within that range is matched. The IP Manager parses CIDR notation and performs subnet containment checks. Individual IP blocks use exact string matching for maximum performance."]}),(0,b.jsx)("h2",{id:"full-configuration",children:"Full Configuration Example"}),(0,b.jsx)("p",{children:"The following example enables all threat intelligence features: profiling, geolocation, IP reputation with auto-blocking, and the WAF for event generation."}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`package main

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
}`}),(0,b.jsx)("h2",{id:"dashboard",children:"Dashboard"}),(0,b.jsx)("p",{children:"The Sentinel dashboard provides two dedicated pages for threat intelligence:"}),(0,b.jsx)("h3",{children:"Actors Page"}),(0,b.jsx)("p",{children:"The Actors page lists all threat actor profiles with sortable columns for IP, risk score, threat count, attack types, country, and last seen time. From this page you can:"}),(0,b.jsxs)("ul",{children:[(0,b.jsx)("li",{children:"Search and filter actors by IP, status, or minimum risk score."}),(0,b.jsx)("li",{children:"View the full profile for any actor, including their complete attack history."}),(0,b.jsx)("li",{children:"Block an actor directly from their profile with a single click."}),(0,b.jsx)("li",{children:"View geographic data and the attack types observed for each actor."})]}),(0,b.jsx)("h3",{children:"IP Management Page"}),(0,b.jsx)("p",{children:"The IP Management page provides a visual interface for managing your blocklist and whitelist:"}),(0,b.jsxs)("ul",{children:[(0,b.jsx)("li",{children:"View all currently blocked IPs and CIDR ranges with block reasons and timestamps."}),(0,b.jsx)("li",{children:"Add new IPs or CIDR ranges to the blocklist with an optional expiration."}),(0,b.jsx)("li",{children:"Unblock IPs that were previously blocked manually or by auto-blocking."}),(0,b.jsx)("li",{children:"Manage the whitelist for trusted IPs."})]}),(0,b.jsxs)("p",{children:["Access these pages at"," ",(0,b.jsx)("code",{children:"http://localhost:8080/sentinel/ui"})," and navigate to the Actors or IP Management sections."]}),(0,b.jsx)("h2",{id:"api",children:"API Reference"}),(0,b.jsxs)("p",{children:["All threat intelligence endpoints require authentication via the dashboard JWT token. Include the token in the ",(0,b.jsx)("code",{children:"Authorization"})," header as"," ",(0,b.jsx)("code",{children:"Bearer <token>"}),"."]}),(0,b.jsx)("h3",{children:"List Actors"}),(0,b.jsx)("p",{children:"Returns a paginated list of threat actor profiles with optional filtering."}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Property"}),(0,b.jsx)("th",{children:"Value"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Endpoint"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"GET /sentinel/api/actors"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Query Params"}),(0,b.jsxs)("td",{children:[(0,b.jsx)("code",{children:"status"}),", ",(0,b.jsx)("code",{children:"min_risk"}),", ",(0,b.jsx)("code",{children:"search"}),","," ",(0,b.jsx)("code",{children:"page"}),", ",(0,b.jsx)("code",{children:"page_size"})]})]})]})]}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# List all actors, sorted by default
curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/actors?page=1&page_size=20"

# Filter by minimum risk score
curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/actors?min_risk=50"

# Filter by status
curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/actors?status=Active"`}),(0,b.jsx)(c.default,{language:"json",filename:"Response",showLineNumbers:!1,code:`{
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
}`}),(0,b.jsx)("h3",{children:"Get Actor by IP"}),(0,b.jsx)("p",{children:"Returns the full profile for a specific threat actor."}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Property"}),(0,b.jsx)("th",{children:"Value"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Endpoint"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"GET /sentinel/api/actors/:ip"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"URL Param"}),(0,b.jsxs)("td",{children:[(0,b.jsx)("code",{children:":ip"})," — the IP address of the actor"]})]})]})]}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/actors/203.0.113.50"`}),(0,b.jsx)("h3",{children:"Block Actor"}),(0,b.jsx)("p",{children:"Blocks a threat actor by IP. The IP is added to the blocklist and all future requests from this IP are rejected."}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Property"}),(0,b.jsx)("th",{children:"Value"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Endpoint"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"POST /sentinel/api/actors/:ip/block"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"URL Param"}),(0,b.jsxs)("td",{children:[(0,b.jsx)("code",{children:":ip"})," — the IP address to block"]})]})]})]}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`curl -s -X POST -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/actors/203.0.113.50/block"`}),(0,b.jsx)(c.default,{language:"json",filename:"Response",showLineNumbers:!1,code:`{
  "message": "Actor blocked"
}`}),(0,b.jsx)("h3",{children:"Actor Request History"}),(0,b.jsx)("p",{children:"Returns the threat events associated with a specific actor IP."}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Property"}),(0,b.jsx)("th",{children:"Value"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Endpoint"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"GET /sentinel/api/actors/:ip/requests"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"URL Param"}),(0,b.jsxs)("td",{children:[(0,b.jsx)("code",{children:":ip"})," — the IP address of the actor"]})]})]})]}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/actors/203.0.113.50/requests"`}),(0,b.jsx)("h3",{children:"List Blocked IPs"}),(0,b.jsx)("p",{children:"Returns all currently blocked IPs and CIDR ranges."}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Property"}),(0,b.jsx)("th",{children:"Value"})]})}),(0,b.jsx)("tbody",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Endpoint"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"GET /sentinel/api/ip/blocked"})})]})})]}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/ip/blocked"`}),(0,b.jsx)(c.default,{language:"json",filename:"Response",showLineNumbers:!1,code:`{
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
}`}),(0,b.jsx)("h3",{children:"Block IP"}),(0,b.jsx)("p",{children:"Adds an IP or CIDR range to the blocklist."}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Property"}),(0,b.jsx)("th",{children:"Value"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Endpoint"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"POST /sentinel/api/ip/block"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Body"}),(0,b.jsxs)("td",{children:["JSON with ",(0,b.jsx)("code",{children:"ip"})," (required), ",(0,b.jsx)("code",{children:"reason"}),", ",(0,b.jsx)("code",{children:"expiry"})," (optional, RFC3339)"]})]})]})]}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Block a single IP
curl -s -X POST -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json" \\
  -d '{"ip": "203.0.113.75", "reason": "Manual block"}' \\
  "http://localhost:8080/sentinel/api/ip/block"

# Block a CIDR range with expiration
curl -s -X POST -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json" \\
  -d '{"ip": "198.51.100.0/24", "reason": "Temporary block", "expiry": "2025-02-15T00:00:00Z"}' \\
  "http://localhost:8080/sentinel/api/ip/block"`}),(0,b.jsx)("h3",{children:"Unblock IP"}),(0,b.jsxs)("p",{children:["Removes an IP or CIDR range from the blocklist. For CIDR ranges, replace ",(0,b.jsx)("code",{children:"/"})," ","with ",(0,b.jsx)("code",{children:"_"})," in the URL parameter (e.g., ",(0,b.jsx)("code",{children:"198.51.100.0_24"}),")."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Property"}),(0,b.jsx)("th",{children:"Value"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Endpoint"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"DELETE /sentinel/api/ip/block/:ip"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"URL Param"}),(0,b.jsxs)("td",{children:[(0,b.jsx)("code",{children:":ip"})," — the IP or CIDR (with ",(0,b.jsx)("code",{children:"/"})," replaced by ",(0,b.jsx)("code",{children:"_"}),")"]})]})]})]}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Unblock a single IP
curl -s -X DELETE -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/ip/block/203.0.113.75"

# Unblock a CIDR range (replace / with _)
curl -s -X DELETE -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/ip/block/198.51.100.0_24"`}),(0,b.jsx)("h3",{children:"IP Reputation Lookup"}),(0,b.jsx)("p",{children:"Retrieves the AbuseIPDB reputation data for a specific IP (requires IP reputation to be enabled)."}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Property"}),(0,b.jsx)("th",{children:"Value"})]})}),(0,b.jsx)("tbody",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Endpoint"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"GET /sentinel/api/ip/:ip/reputation"})})]})})]}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/ip/203.0.113.50/reputation"`}),(0,b.jsx)("h2",{id:"testing",children:"Testing"}),(0,b.jsx)("p",{children:"After enabling the WAF or any other detection feature, threat actor profiles are created automatically. You can verify the intelligence system is working by triggering a few test events and then querying the actors API."}),(0,b.jsx)("h3",{children:"Step 1: Trigger Security Events"}),(0,b.jsx)("p",{children:"Send a few malicious requests to generate threat events. These will automatically create actor profiles."}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Trigger a SQL injection event
curl -s "http://localhost:8080/api/data?id=1'+OR+'1'='1"

# Trigger an XSS event
curl -s "http://localhost:8080/api/data?q=<script>alert(1)</script>"

# Trigger a path traversal event
curl -s "http://localhost:8080/api/data/../../../../etc/passwd"`}),(0,b.jsx)("h3",{children:"Step 2: Log In to the Dashboard API"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Obtain a JWT token
TOKEN=$(curl -s -X POST http://localhost:8080/sentinel/api/auth/login \\
  -H "Content-Type: application/json" \\
  -d '{"username":"admin","password":"sentinel"}' | jq -r '.token')

echo $TOKEN`}),(0,b.jsx)("h3",{children:"Step 3: View Actor Profiles"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# List all actors
curl -s -H "Authorization: Bearer $TOKEN" \\
  "http://localhost:8080/sentinel/api/actors" | jq .

# View a specific actor (use your test IP, likely 127.0.0.1)
curl -s -H "Authorization: Bearer $TOKEN" \\
  "http://localhost:8080/sentinel/api/actors/127.0.0.1" | jq .

# View the threat history for an actor
curl -s -H "Authorization: Bearer $TOKEN" \\
  "http://localhost:8080/sentinel/api/actors/127.0.0.1/requests" | jq .`}),(0,b.jsx)("h3",{children:"Step 4: Test IP Blocking"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Block an actor
curl -s -X POST -H "Authorization: Bearer $TOKEN" \\
  "http://localhost:8080/sentinel/api/actors/203.0.113.50/block" | jq .

# Verify the IP appears in the blocklist
curl -s -H "Authorization: Bearer $TOKEN" \\
  "http://localhost:8080/sentinel/api/ip/blocked" | jq .

# Unblock the IP
curl -s -X DELETE -H "Authorization: Bearer $TOKEN" \\
  "http://localhost:8080/sentinel/api/ip/block/203.0.113.50" | jq .`}),(0,b.jsxs)(d.default,{type:"danger",title:"Local Testing Note",children:["When testing locally, all requests originate from ",(0,b.jsx)("code",{children:"127.0.0.1"})," or"," ",(0,b.jsx)("code",{children:"::1"}),", so all test events will be attributed to a single actor profile. Geolocation lookups are skipped for private and loopback IPs. To test with realistic geographic data, deploy to a staging environment and send requests from external IPs."]}),(0,b.jsx)("h2",{children:"Next Steps"}),(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/waf",children:"WAF"})," — Configure the WAF rules that generate threat events"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/auth-shield",children:"Auth Shield"})," — Protect login endpoints from brute-force attacks"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/anomaly-detection",children:"Anomaly Detection"})," — Add behavioral analysis for advanced threat detection"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/alerting",children:"Alerting"})," — Get notified when high-risk actors are detected"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/the-dashboard",children:"Dashboard"})," — Explore the Actors and IP Management pages"]})]})]})}a.s(["default",()=>e,"metadata",0,{title:"Threat Intelligence - Sentinel Docs"}])}];

//# sourceMappingURL=app_docs_threat-intelligence_page_jsx_323b277e._.js.map