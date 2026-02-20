module.exports=[99845,a=>{"use strict";var b=a.i(81332),c=a.i(17924),d=a.i(64939);function e(){return(0,b.jsxs)(b.Fragment,{children:[(0,b.jsx)("h1",{children:"Anomaly Detection"}),(0,b.jsx)("p",{children:"Sentinel includes a statistical anomaly detection system that identifies unusual traffic patterns by comparing real-time user activity against learned behavioral baselines. Unlike the WAF, which matches known attack signatures, anomaly detection catches previously unseen threats by flagging activity that deviates from what is normal for each user."}),(0,b.jsxs)("p",{children:["The detector builds per-user baselines from historical activity data — typical active hours, frequently accessed routes, source IPs, geographic locations, and request velocity. When new activity diverges significantly from these baselines, Sentinel emits a threat event with type"," ",(0,b.jsx)("code",{children:"AnomalyDetected"}),"."]}),(0,b.jsxs)(d.default,{type:"info",title:"Requires a UserExtractor",children:["Anomaly detection operates on a per-user basis. You must configure a"," ",(0,b.jsx)("code",{children:"UserExtractor"})," in your Sentinel config so the system can associate requests with user identities. Without it, the anomaly detector has no user context and will not run."]}),(0,b.jsx)("h2",{id:"configuration",children:"Configuration"}),(0,b.jsxs)("p",{children:["Anomaly detection is disabled by default. Enable it by setting ",(0,b.jsx)("code",{children:"Enabled: true"})," in your ",(0,b.jsx)("code",{children:"AnomalyConfig"}),". The minimal configuration uses all defaults:"]}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`package main

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
}`}),(0,b.jsx)("h3",{children:"AnomalyConfig Reference"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsx)("td",{children:"Enables anomaly detection. When false, the detector is a no-op."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Sensitivity"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"AnomalySensitivity"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"AnomalySensitivityMedium"})}),(0,b.jsx)("td",{children:"Controls the scoring threshold that triggers an anomaly event. See sensitivity levels below."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"LearningPeriod"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"time.Duration"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"7 * 24 * time.Hour"})}),(0,b.jsx)("td",{children:"How far back to look when computing a user's behavioral baseline. Longer periods produce more stable baselines but are slower to adapt."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Checks"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"[]AnomalyCheckType"})}),(0,b.jsx)("td",{children:"All checks enabled"}),(0,b.jsx)("td",{children:"Which anomaly checks to run. If empty, all check types are enabled. Specify a subset to narrow detection scope."})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"config.go",code:`Anomaly: sentinel.AnomalyConfig{
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
}`}),(0,b.jsx)("h2",{id:"sensitivity",children:"Sensitivity Levels"}),(0,b.jsx)("p",{children:"Sensitivity controls the anomaly score threshold required to emit a threat event. Each anomaly check contributes a score, and the total is compared against the threshold. Lower thresholds trigger more alerts."}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Level"}),(0,b.jsx)("th",{children:"Constant"}),(0,b.jsx)("th",{children:"Threshold"}),(0,b.jsx)("th",{children:"Behavior"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Low"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.AnomalySensitivityLow"})}),(0,b.jsx)("td",{children:"50"}),(0,b.jsx)("td",{children:"Only the most significant anomalies trigger events. Fewer alerts, less noise. Best for high-traffic applications where some deviation is normal."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Medium"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.AnomalySensitivityMedium"})}),(0,b.jsx)("td",{children:"30"}),(0,b.jsx)("td",{children:"Balanced detection. Catches meaningful deviations without overwhelming you with alerts. Recommended starting point."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"High"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.AnomalySensitivityHigh"})}),(0,b.jsx)("td",{children:"15"}),(0,b.jsx)("td",{children:"Aggressive detection. Catches subtle anomalies but produces more alerts. Best for high-security environments or during active incident investigation."})]})]})]}),(0,b.jsxs)(d.default,{type:"success",title:"Recommended Starting Point",children:["Start with ",(0,b.jsx)("code",{children:"AnomalySensitivityMedium"}),". Monitor the anomaly events in the dashboard for a week to understand your application's normal patterns, then adjust up or down based on the signal-to-noise ratio you observe."]}),(0,b.jsx)("h2",{id:"checks",children:"What Gets Detected"}),(0,b.jsx)("p",{children:"The anomaly detector runs a configurable set of behavioral checks against each user activity event. Each check compares one aspect of the current request against the user's baseline and returns a score from 0 (normal) to 30 (highly anomalous). Scores from all checks are summed (capped at 100) and compared against the sensitivity threshold."}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Check"}),(0,b.jsx)("th",{children:"Constant"}),(0,b.jsx)("th",{children:"Max Score"}),(0,b.jsx)("th",{children:"What It Detects"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Off-Hours Access"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CheckOffHoursAccess"})}),(0,b.jsx)("td",{children:"30"}),(0,b.jsx)("td",{children:"Activity during hours when the user is rarely active. If the current hour represents less than 1% of baseline activity, the full score is assigned; less than 3% yields a partial score of 15."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Unusual Route Access"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CheckUnusualAccess"})}),(0,b.jsx)("td",{children:"25"}),(0,b.jsx)("td",{children:"Access to routes (method + path) that the user has never accessed before during the learning period. Useful for detecting lateral movement or account compromise."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Velocity Anomaly"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CheckVelocityAnomaly"})}),(0,b.jsx)("td",{children:"25"}),(0,b.jsx)("td",{children:"Request rate spikes that exceed 3x the user's average rate for the current time of day. Catches automated scraping, credential stuffing, or bot activity on a compromised account."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Impossible Travel"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CheckImpossibleTravel"})}),(0,b.jsx)("td",{children:"30"}),(0,b.jsx)("td",{children:"Activity from a new IP address, especially from a country the user has never connected from. A new country yields a score of 30; a new IP in the same country yields 10."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Data Exfiltration"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CheckDataExfiltration"})}),(0,b.jsx)("td",{children:"20"}),(0,b.jsx)("td",{children:"Unusually large response sizes or durations that exceed 5x the user's baseline average. Indicates potential bulk data extraction."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Credential Stuffing"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CheckCredentialStuffing"})}),(0,b.jsx)("td",{children:"--"}),(0,b.jsx)("td",{children:"Reserved check type for detecting credential stuffing patterns. Configure via Auth Shield for full brute-force protection."})]})]})]}),(0,b.jsx)(c.default,{language:"go",showLineNumbers:!1,code:`// Enable only specific checks
Checks: []sentinel.AnomalyCheckType{
    sentinel.CheckOffHoursAccess,
    sentinel.CheckImpossibleTravel,
    // Omit checks that are not relevant to your application
}`}),(0,b.jsxs)(d.default,{type:"warning",title:"Minimum Baseline Requirement",children:["The anomaly detector requires at least ",(0,b.jsx)("strong",{children:"10 historical activity records"})," for a user before it will evaluate checks. Users with fewer records are silently skipped. This prevents false positives on new users or accounts with very little history."]}),(0,b.jsx)("h2",{id:"how-it-works",children:"How It Works"}),(0,b.jsx)("p",{children:"The anomaly detector operates as a handler in Sentinel's asynchronous event pipeline. It does not sit in the HTTP request path and adds no latency to your responses."}),(0,b.jsxs)("ol",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Activity Tracking"})," — When a request arrives, Sentinel records a"," ",(0,b.jsx)("code",{children:"UserActivity"})," event containing the user ID, timestamp, IP address, HTTP method, path, response duration, and geographic country (if geo is enabled)."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Pipeline Dispatch"})," — The activity event is sent to the async pipeline via a non-blocking ring buffer. This decouples detection from request handling."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Baseline Computation"})," — The detector loads the user's historical activity from storage (within the configured ",(0,b.jsx)("code",{children:"LearningPeriod"}),") and computes a"," ",(0,b.jsx)("code",{children:"UserBaseline"}),". Baselines are cached for 1 hour to avoid repeated computation."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Check Evaluation"})," — Each enabled check compares the current activity against the baseline and returns a score. Scores are summed and capped at 100."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Threshold Comparison"})," — If the total score meets or exceeds the sensitivity threshold, a ",(0,b.jsx)("code",{children:"ThreatEvent"})," is emitted with type"," ",(0,b.jsx)("code",{children:"AnomalyDetected"}),"."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Event Processing"})," — The threat event flows through the rest of the pipeline: it is persisted to storage, updates the threat actor profile, recalculates the security score, and triggers alerts if the severity meets the alerting threshold."]})]}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Anomaly detection flow:
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
#                                                  Persist + Alert`}),(0,b.jsx)(d.default,{type:"info",title:"Non-Blocking Detection",children:"The anomaly detector runs entirely outside the HTTP request path. Activity recording uses a non-blocking ring buffer, so detection never slows down your API responses, even when computing baselines from large activity histories."}),(0,b.jsx)("h2",{id:"baselines",children:"Baselines"}),(0,b.jsxs)("p",{children:["A ",(0,b.jsx)("code",{children:"UserBaseline"})," captures the behavioral profile for a single user. It is computed from all activity within the ",(0,b.jsx)("code",{children:"LearningPeriod"})," and cached in memory for 1 hour before being recomputed."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Baseline Field"}),(0,b.jsx)("th",{children:"What It Tracks"}),(0,b.jsx)("th",{children:"Used By"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ActiveHours"})}),(0,b.jsx)("td",{children:"Distribution of activity across hours of the day (0-23)"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CheckOffHoursAccess"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"TypicalRoutes"})}),(0,b.jsx)("td",{children:"Set of method+path combinations the user has accessed"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CheckUnusualAccess"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"AvgRequestsPerHour"})}),(0,b.jsx)("td",{children:"Average request rate across the learning period"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CheckVelocityAnomaly"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"SourceIPs"})}),(0,b.jsx)("td",{children:"Set of IP addresses the user has connected from"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CheckImpossibleTravel"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Countries"})}),(0,b.jsx)("td",{children:"Set of countries (by geo lookup) the user has connected from"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CheckImpossibleTravel"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"AvgResponseSize"})}),(0,b.jsx)("td",{children:"Average response duration/size across the learning period"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CheckDataExfiltration"})})]})]})]}),(0,b.jsxs)("p",{children:["The ",(0,b.jsx)("code",{children:"LearningPeriod"})," determines the time window for baseline computation. The default is 7 days. A longer period (e.g., 14 or 30 days) produces more stable baselines but adapts more slowly to legitimate changes in user behavior."]}),(0,b.jsx)(c.default,{language:"go",showLineNumbers:!1,code:`// Short learning period — adapts quickly, less stable
LearningPeriod: 3 * 24 * time.Hour,  // 3 days

// Default — balanced
LearningPeriod: 7 * 24 * time.Hour,  // 7 days

// Long learning period — very stable, slow to adapt
LearningPeriod: 30 * 24 * time.Hour, // 30 days`}),(0,b.jsx)("h2",{id:"events",children:"Anomaly Events"}),(0,b.jsxs)("p",{children:["When an anomaly is detected, Sentinel emits a ",(0,b.jsx)("code",{children:"ThreatEvent"})," with the threat type"," ",(0,b.jsx)("code",{children:"AnomalyDetected"}),". These events appear in the dashboard alongside WAF detections and other security events."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Event Field"}),(0,b.jsx)("th",{children:"Value"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ThreatTypes"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:'["AnomalyDetected"]'})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Severity"})}),(0,b.jsx)("td",{children:"Computed from the anomaly score: Critical (≥80), High (≥60), Medium (≥30), Low (<30)"})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Confidence"})}),(0,b.jsx)("td",{children:"The raw anomaly score (0-100), representing how far the activity deviates from baseline"})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Evidence"})}),(0,b.jsx)("td",{children:"Contains the anomaly score and the list of checks that contributed to it"})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Blocked"})}),(0,b.jsxs)("td",{children:[(0,b.jsx)("code",{children:"false"})," — anomaly events are informational; they do not block requests"]})]})]})]}),(0,b.jsx)("h3",{children:"Severity Mapping"}),(0,b.jsx)("p",{children:"The anomaly score is mapped to a severity level using the following thresholds:"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Score Range"}),(0,b.jsx)("th",{children:"Severity"}),(0,b.jsx)("th",{children:"Interpretation"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"80 - 100"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Critical"})}),(0,b.jsx)("td",{children:"Multiple strong anomaly signals. Very likely a compromised account or active attack."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"60 - 79"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"High"})}),(0,b.jsx)("td",{children:"Significant deviation from baseline. Warrants immediate investigation."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"30 - 59"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Medium"})}),(0,b.jsx)("td",{children:"Moderate deviation. Could be a legitimate change in behavior or early sign of compromise."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"0 - 29"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Low"})}),(0,b.jsx)("td",{children:"Minor deviation. Usually benign but logged for audit purposes."})]})]})]}),(0,b.jsxs)(d.default,{type:"info",title:"Anomaly Events Are Non-Blocking",children:["Anomaly events are always informational — they never block requests. The detector flags suspicious behavior so you can investigate, but it does not interrupt user sessions. To automatically respond to anomalies, pair anomaly detection with the"," ",(0,b.jsx)("a",{href:"/docs/alerting",children:"alerting system"})," to receive notifications when high-severity anomalies occur."]}),(0,b.jsx)("h2",{id:"full-example",children:"Full Configuration Example"}),(0,b.jsx)("p",{children:"Below is a complete example that enables anomaly detection alongside other Sentinel features:"}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`package main

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
}`}),(0,b.jsx)("h2",{id:"testing",children:"Testing Considerations"}),(0,b.jsx)("p",{children:"Anomaly detection requires sufficient historical data to produce meaningful baselines. This makes it harder to test than the WAF or rate limiter, which respond immediately. Here are strategies for testing effectively."}),(0,b.jsx)("h3",{children:"Building a Baseline"}),(0,b.jsx)("p",{children:"The detector requires at least 10 activity records for a user before it will evaluate checks. In a test environment, you can seed activity data by sending authenticated requests over a consistent pattern, then introducing an anomalous request to verify detection."}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Seed baseline activity (repeat over multiple hours/days for a realistic baseline)
for i in $(seq 1 20); do
    curl -s -H "X-User-ID: testuser" http://localhost:8080/api/data > /dev/null
    sleep 1
done

# Now trigger an anomaly — access from a different IP or unusual route
curl -s -H "X-User-ID: testuser" http://localhost:8080/admin/settings
# Check the Sentinel dashboard for an AnomalyDetected event`}),(0,b.jsx)("h3",{children:"Shorter Learning Period for Tests"}),(0,b.jsxs)("p",{children:["Use a short ",(0,b.jsx)("code",{children:"LearningPeriod"})," in test environments so baselines are computed from a smaller window of data:"]}),(0,b.jsx)(c.default,{language:"go",showLineNumbers:!1,code:`// In tests, use a short learning period
Anomaly: sentinel.AnomalyConfig{
    Enabled:        true,
    Sensitivity:    sentinel.AnomalySensitivityHigh, // Catch everything
    LearningPeriod: 1 * time.Hour,                  // Short window for tests
}`}),(0,b.jsx)("h3",{children:"Unit Testing"}),(0,b.jsxs)("p",{children:["You can test the anomaly detector programmatically by creating a store, seeding activity data, and calling ",(0,b.jsx)("code",{children:"CheckActivity"})," directly:"]}),(0,b.jsx)(c.default,{language:"go",filename:"anomaly_test.go",code:`func TestAnomalyDetection(t *testing.T) {
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
}`}),(0,b.jsxs)(d.default,{type:"warning",title:"Timing in Tests",children:["The anomaly detector emits threat events asynchronously through the pipeline. In unit tests, add a short ",(0,b.jsx)("code",{children:"time.Sleep"})," (e.g., 100ms) after calling ",(0,b.jsx)("code",{children:"CheckActivity"})," ","to allow the pipeline to process the event before asserting on results."]}),(0,b.jsx)("h2",{children:"Next Steps"}),(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/configuration",children:"Configuration Reference"})," — Full AnomalyConfig field reference"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/auth-shield",children:"Auth Shield"})," — Brute-force and credential stuffing protection"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/waf",children:"WAF"})," — Signature-based attack detection to complement anomaly detection"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/alerting",children:"Alerting"})," — Get notified when anomalies are detected"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/the-dashboard",children:"Dashboard"})," — View anomaly events and user baselines"]})]})]})}a.s(["default",()=>e,"metadata",0,{title:"Anomaly Detection - Sentinel Docs"}])}];

//# sourceMappingURL=app_docs_anomaly-detection_page_jsx_87b8a8a3._.js.map