1:"$Sreact.fragment"
2:I[99151,["/_next/static/chunks/4cc5a908347f559b.js","/_next/static/chunks/c23263069b7f7ba3.js","/_next/static/chunks/2425b678dfc0c3cf.js"],"default"]
38:I[35417,["/_next/static/chunks/26ca110782d86623.js","/_next/static/chunks/81f0f13d25d49d65.js"],"OutletBoundary"]
39:"$Sreact.suspense"
0:{"buildId":"5Swj18oapgqGqSZX8fol6","rsc":["$","$1","c",{"children":[[["$","h1",null,{"children":"Anomaly Detection"}],["$","p",null,{"children":"Sentinel includes a statistical anomaly detection system that identifies unusual traffic patterns by comparing real-time user activity against learned behavioral baselines. Unlike the WAF, which matches known attack signatures, anomaly detection catches previously unseen threats by flagging activity that deviates from what is normal for each user."}],["$","p",null,{"children":["The detector builds per-user baselines from historical activity data — typical active hours, frequently accessed routes, source IPs, geographic locations, and request velocity. When new activity diverges significantly from these baselines, Sentinel emits a threat event with type"," ",["$","code",null,{"children":"AnomalyDetected"}],"."]}],["$","div",null,{"className":"my-4 rounded-lg border p-4 bg-blue-50 dark:bg-blue-950/30 border-blue-200 dark:border-blue-800","children":["$","div",null,{"className":"flex items-start gap-3","children":[["$","svg",null,{"xmlns":"http://www.w3.org/2000/svg","width":18,"height":18,"viewBox":"0 0 24 24","fill":"none","stroke":"currentColor","strokeWidth":2,"strokeLinecap":"round","strokeLinejoin":"round","className":"lucide lucide-info mt-0.5 flex-shrink-0 text-blue-500","children":[["$","circle","1mglay",{"cx":"12","cy":"12","r":"10"}],["$","path","1dtifu",{"d":"M12 16v-4"}],["$","path","e9boi3",{"d":"M12 8h.01"}],"$undefined"]}],["$","div",null,{"children":[["$","p",null,{"className":"font-semibold text-sm mb-1 text-blue-800 dark:text-blue-300","children":"Requires a UserExtractor"}],["$","div",null,{"className":"text-sm text-gray-700 dark:text-gray-300","children":["Anomaly detection operates on a per-user basis. You must configure a"," ",["$","code",null,{"children":"UserExtractor"}]," in your Sentinel config so the system can associate requests with user identities. Without it, the anomaly detector has no user context and will not run."]}]]}]]}]}],["$","h2",null,{"id":"configuration","children":"Configuration"}],["$","p",null,{"children":["Anomaly detection is disabled by default. Enable it by setting ",["$","code",null,{"children":"Enabled: true"}]," in your ",["$","code",null,{"children":"AnomalyConfig"}],". The minimal configuration uses all defaults:"]}],["$","$L2",null,{"language":"go","filename":"main.go","code":"package main\n\nimport (\n    \"time\"\n\n    sentinel \"github.com/MUKE-coder/sentinel\"\n    \"github.com/gin-gonic/gin\"\n)\n\nfunc main() {\n    r := gin.Default()\n\n    sentinel.Mount(r, nil, sentinel.Config{\n        Anomaly: sentinel.AnomalyConfig{\n            Enabled:    true,\n            Sensitivity: sentinel.AnomalySensitivityMedium,\n        },\n        UserExtractor: func(c *gin.Context) *sentinel.UserContext {\n            return &sentinel.UserContext{\n                ID:    c.GetHeader(\"X-User-ID\"),\n                Email: c.GetHeader(\"X-User-Email\"),\n                Role:  c.GetHeader(\"X-User-Role\"),\n            }\n        },\n    })\n\n    r.GET(\"/api/data\", func(c *gin.Context) {\n        c.JSON(200, gin.H{\"status\": \"ok\"})\n    })\n\n    r.Run(\":8080\")\n}"}],["$","h3",null,{"children":"AnomalyConfig Reference"}],["$","table",null,{"children":[["$","thead",null,{"children":["$","tr",null,{"children":[["$","th",null,{"children":"Field"}],["$","th",null,{"children":"Type"}],["$","th",null,{"children":"Default"}],["$","th",null,{"children":"Description"}]]}]}],["$","tbody",null,{"children":[["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"Enabled"}]}],["$","td",null,{"children":["$","code",null,{"children":"bool"}]}],["$","td",null,{"children":["$","code",null,{"children":"false"}]}],["$","td",null,{"children":"Enables anomaly detection. When false, the detector is a no-op."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"Sensitivity"}]}],["$","td",null,{"children":["$","code",null,{"children":"AnomalySensitivity"}]}],["$","td",null,{"children":"$L3"}],"$L4"]}],"$L5","$L6"]}]]}],"$L7","$L8","$L9","$La","$Lb","$Lc","$Ld","$Le","$Lf","$L10","$L11","$L12","$L13","$L14","$L15","$L16","$L17","$L18","$L19","$L1a","$L1b","$L1c","$L1d","$L1e","$L1f","$L20","$L21","$L22","$L23","$L24","$L25","$L26","$L27","$L28","$L29","$L2a","$L2b","$L2c","$L2d","$L2e","$L2f","$L30","$L31","$L32"],["$L33"],"$L34"]}],"loading":null,"isPartial":false}
3:["$","code",null,{"children":"AnomalySensitivityMedium"}]
4:["$","td",null,{"children":"Controls the scoring threshold that triggers an anomaly event. See sensitivity levels below."}]
5:["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"LearningPeriod"}]}],["$","td",null,{"children":["$","code",null,{"children":"time.Duration"}]}],["$","td",null,{"children":["$","code",null,{"children":"7 * 24 * time.Hour"}]}],["$","td",null,{"children":"How far back to look when computing a user's behavioral baseline. Longer periods produce more stable baselines but are slower to adapt."}]]}]
6:["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"Checks"}]}],["$","td",null,{"children":["$","code",null,{"children":"[]AnomalyCheckType"}]}],["$","td",null,{"children":"All checks enabled"}],["$","td",null,{"children":"Which anomaly checks to run. If empty, all check types are enabled. Specify a subset to narrow detection scope."}]]}]
7:["$","$L2",null,{"language":"go","filename":"config.go","code":"Anomaly: sentinel.AnomalyConfig{\n    Enabled:        true,\n    Sensitivity:    sentinel.AnomalySensitivityMedium,\n    LearningPeriod: 14 * 24 * time.Hour, // 2 weeks of history\n    Checks: []sentinel.AnomalyCheckType{\n        sentinel.CheckOffHoursAccess,\n        sentinel.CheckUnusualAccess,\n        sentinel.CheckVelocityAnomaly,\n        sentinel.CheckImpossibleTravel,\n        sentinel.CheckDataExfiltration,\n    },\n}"}]
8:["$","h2",null,{"id":"sensitivity","children":"Sensitivity Levels"}]
9:["$","p",null,{"children":"Sensitivity controls the anomaly score threshold required to emit a threat event. Each anomaly check contributes a score, and the total is compared against the threshold. Lower thresholds trigger more alerts."}]
a:["$","table",null,{"children":[["$","thead",null,{"children":["$","tr",null,{"children":[["$","th",null,{"children":"Level"}],["$","th",null,{"children":"Constant"}],["$","th",null,{"children":"Threshold"}],["$","th",null,{"children":"Behavior"}]]}]}],["$","tbody",null,{"children":[["$","tr",null,{"children":[["$","td",null,{"children":"Low"}],["$","td",null,{"children":["$","code",null,{"children":"sentinel.AnomalySensitivityLow"}]}],["$","td",null,{"children":"50"}],["$","td",null,{"children":"Only the most significant anomalies trigger events. Fewer alerts, less noise. Best for high-traffic applications where some deviation is normal."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":"Medium"}],["$","td",null,{"children":["$","code",null,{"children":"sentinel.AnomalySensitivityMedium"}]}],["$","td",null,{"children":"30"}],["$","td",null,{"children":"Balanced detection. Catches meaningful deviations without overwhelming you with alerts. Recommended starting point."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":"High"}],["$","td",null,{"children":["$","code",null,{"children":"sentinel.AnomalySensitivityHigh"}]}],["$","td",null,{"children":"15"}],["$","td",null,{"children":"Aggressive detection. Catches subtle anomalies but produces more alerts. Best for high-security environments or during active incident investigation."}]]}]]}]]}]
b:["$","div",null,{"className":"my-4 rounded-lg border p-4 bg-green-50 dark:bg-green-950/30 border-green-200 dark:border-green-800","children":["$","div",null,{"className":"flex items-start gap-3","children":[["$","svg",null,{"xmlns":"http://www.w3.org/2000/svg","width":18,"height":18,"viewBox":"0 0 24 24","fill":"none","stroke":"currentColor","strokeWidth":2,"strokeLinecap":"round","strokeLinejoin":"round","className":"lucide lucide-circle-check-big mt-0.5 flex-shrink-0 text-green-500","children":[["$","path","yps3ct",{"d":"M21.801 10A10 10 0 1 1 17 3.335"}],["$","path","1pflzl",{"d":"m9 11 3 3L22 4"}],"$undefined"]}],["$","div",null,{"children":[["$","p",null,{"className":"font-semibold text-sm mb-1 text-green-800 dark:text-green-300","children":"Recommended Starting Point"}],["$","div",null,{"className":"text-sm text-gray-700 dark:text-gray-300","children":["Start with ",["$","code",null,{"children":"AnomalySensitivityMedium"}],". Monitor the anomaly events in the dashboard for a week to understand your application's normal patterns, then adjust up or down based on the signal-to-noise ratio you observe."]}]]}]]}]}]
c:["$","h2",null,{"id":"checks","children":"What Gets Detected"}]
d:["$","p",null,{"children":"The anomaly detector runs a configurable set of behavioral checks against each user activity event. Each check compares one aspect of the current request against the user's baseline and returns a score from 0 (normal) to 30 (highly anomalous). Scores from all checks are summed (capped at 100) and compared against the sensitivity threshold."}]
e:["$","table",null,{"children":[["$","thead",null,{"children":["$","tr",null,{"children":[["$","th",null,{"children":"Check"}],["$","th",null,{"children":"Constant"}],["$","th",null,{"children":"Max Score"}],["$","th",null,{"children":"What It Detects"}]]}]}],["$","tbody",null,{"children":[["$","tr",null,{"children":[["$","td",null,{"children":"Off-Hours Access"}],["$","td",null,{"children":["$","code",null,{"children":"CheckOffHoursAccess"}]}],["$","td",null,{"children":"30"}],["$","td",null,{"children":"Activity during hours when the user is rarely active. If the current hour represents less than 1% of baseline activity, the full score is assigned; less than 3% yields a partial score of 15."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":"Unusual Route Access"}],["$","td",null,{"children":["$","code",null,{"children":"CheckUnusualAccess"}]}],["$","td",null,{"children":"25"}],["$","td",null,{"children":"Access to routes (method + path) that the user has never accessed before during the learning period. Useful for detecting lateral movement or account compromise."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":"Velocity Anomaly"}],["$","td",null,{"children":["$","code",null,{"children":"CheckVelocityAnomaly"}]}],["$","td",null,{"children":"25"}],["$","td",null,{"children":"Request rate spikes that exceed 3x the user's average rate for the current time of day. Catches automated scraping, credential stuffing, or bot activity on a compromised account."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":"Impossible Travel"}],["$","td",null,{"children":["$","code",null,{"children":"CheckImpossibleTravel"}]}],["$","td",null,{"children":"30"}],["$","td",null,{"children":"Activity from a new IP address, especially from a country the user has never connected from. A new country yields a score of 30; a new IP in the same country yields 10."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":"Data Exfiltration"}],["$","td",null,{"children":["$","code",null,{"children":"CheckDataExfiltration"}]}],["$","td",null,{"children":"20"}],["$","td",null,{"children":"Unusually large response sizes or durations that exceed 5x the user's baseline average. Indicates potential bulk data extraction."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":"Credential Stuffing"}],["$","td",null,{"children":["$","code",null,{"children":"CheckCredentialStuffing"}]}],["$","td",null,{"children":"--"}],["$","td",null,{"children":"Reserved check type for detecting credential stuffing patterns. Configure via Auth Shield for full brute-force protection."}]]}]]}]]}]
f:["$","$L2",null,{"language":"go","showLineNumbers":false,"code":"// Enable only specific checks\nChecks: []sentinel.AnomalyCheckType{\n    sentinel.CheckOffHoursAccess,\n    sentinel.CheckImpossibleTravel,\n    // Omit checks that are not relevant to your application\n}"}]
10:["$","div",null,{"className":"my-4 rounded-lg border p-4 bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-800","children":["$","div",null,{"className":"flex items-start gap-3","children":[["$","svg",null,{"xmlns":"http://www.w3.org/2000/svg","width":18,"height":18,"viewBox":"0 0 24 24","fill":"none","stroke":"currentColor","strokeWidth":2,"strokeLinecap":"round","strokeLinejoin":"round","className":"lucide lucide-triangle-alert mt-0.5 flex-shrink-0 text-amber-500","children":[["$","path","wmoenq",{"d":"m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"}],["$","path","juzpu7",{"d":"M12 9v4"}],["$","path","p32p05",{"d":"M12 17h.01"}],"$undefined"]}],["$","div",null,{"children":[["$","p",null,{"className":"font-semibold text-sm mb-1 text-amber-800 dark:text-amber-300","children":"Minimum Baseline Requirement"}],["$","div",null,{"className":"text-sm text-gray-700 dark:text-gray-300","children":["The anomaly detector requires at least ",["$","strong",null,{"children":"10 historical activity records"}]," for a user before it will evaluate checks. Users with fewer records are silently skipped. This prevents false positives on new users or accounts with very little history."]}]]}]]}]}]
11:["$","h2",null,{"id":"how-it-works","children":"How It Works"}]
12:["$","p",null,{"children":"The anomaly detector operates as a handler in Sentinel's asynchronous event pipeline. It does not sit in the HTTP request path and adds no latency to your responses."}]
13:["$","ol",null,{"children":[["$","li",null,{"children":[["$","strong",null,{"children":"Activity Tracking"}]," — When a request arrives, Sentinel records a"," ",["$","code",null,{"children":"UserActivity"}]," event containing the user ID, timestamp, IP address, HTTP method, path, response duration, and geographic country (if geo is enabled)."]}],["$","li",null,{"children":[["$","strong",null,{"children":"Pipeline Dispatch"}]," — The activity event is sent to the async pipeline via a non-blocking ring buffer. This decouples detection from request handling."]}],["$","li",null,{"children":[["$","strong",null,{"children":"Baseline Computation"}]," — The detector loads the user's historical activity from storage (within the configured ",["$","code",null,{"children":"LearningPeriod"}],") and computes a"," ",["$","code",null,{"children":"UserBaseline"}],". Baselines are cached for 1 hour to avoid repeated computation."]}],["$","li",null,{"children":[["$","strong",null,{"children":"Check Evaluation"}]," — Each enabled check compares the current activity against the baseline and returns a score. Scores are summed and capped at 100."]}],["$","li",null,{"children":[["$","strong",null,{"children":"Threshold Comparison"}]," — If the total score meets or exceeds the sensitivity threshold, a ",["$","code",null,{"children":"ThreatEvent"}]," is emitted with type"," ",["$","code",null,{"children":"AnomalyDetected"}],"."]}],["$","li",null,{"children":[["$","strong",null,{"children":"Event Processing"}]," — The threat event flows through the rest of the pipeline: it is persisted to storage, updates the threat actor profile, recalculates the security score, and triggers alerts if the severity meets the alerting threshold."]}]]}]
35:T44e,# Anomaly detection flow:
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
#                                                  Persist + Alert14:["$","$L2",null,{"language":"bash","showLineNumbers":false,"code":"$35"}]
15:["$","div",null,{"className":"my-4 rounded-lg border p-4 bg-blue-50 dark:bg-blue-950/30 border-blue-200 dark:border-blue-800","children":["$","div",null,{"className":"flex items-start gap-3","children":[["$","svg",null,{"xmlns":"http://www.w3.org/2000/svg","width":18,"height":18,"viewBox":"0 0 24 24","fill":"none","stroke":"currentColor","strokeWidth":2,"strokeLinecap":"round","strokeLinejoin":"round","className":"lucide lucide-info mt-0.5 flex-shrink-0 text-blue-500","children":[["$","circle","1mglay",{"cx":"12","cy":"12","r":"10"}],["$","path","1dtifu",{"d":"M12 16v-4"}],["$","path","e9boi3",{"d":"M12 8h.01"}],"$undefined"]}],["$","div",null,{"children":[["$","p",null,{"className":"font-semibold text-sm mb-1 text-blue-800 dark:text-blue-300","children":"Non-Blocking Detection"}],["$","div",null,{"className":"text-sm text-gray-700 dark:text-gray-300","children":"The anomaly detector runs entirely outside the HTTP request path. Activity recording uses a non-blocking ring buffer, so detection never slows down your API responses, even when computing baselines from large activity histories."}]]}]]}]}]
16:["$","h2",null,{"id":"baselines","children":"Baselines"}]
17:["$","p",null,{"children":["A ",["$","code",null,{"children":"UserBaseline"}]," captures the behavioral profile for a single user. It is computed from all activity within the ",["$","code",null,{"children":"LearningPeriod"}]," and cached in memory for 1 hour before being recomputed."]}]
18:["$","table",null,{"children":[["$","thead",null,{"children":["$","tr",null,{"children":[["$","th",null,{"children":"Baseline Field"}],["$","th",null,{"children":"What It Tracks"}],["$","th",null,{"children":"Used By"}]]}]}],["$","tbody",null,{"children":[["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"ActiveHours"}]}],["$","td",null,{"children":"Distribution of activity across hours of the day (0-23)"}],["$","td",null,{"children":["$","code",null,{"children":"CheckOffHoursAccess"}]}]]}],["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"TypicalRoutes"}]}],["$","td",null,{"children":"Set of method+path combinations the user has accessed"}],["$","td",null,{"children":["$","code",null,{"children":"CheckUnusualAccess"}]}]]}],["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"AvgRequestsPerHour"}]}],["$","td",null,{"children":"Average request rate across the learning period"}],["$","td",null,{"children":["$","code",null,{"children":"CheckVelocityAnomaly"}]}]]}],["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"SourceIPs"}]}],["$","td",null,{"children":"Set of IP addresses the user has connected from"}],["$","td",null,{"children":["$","code",null,{"children":"CheckImpossibleTravel"}]}]]}],["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"Countries"}]}],["$","td",null,{"children":"Set of countries (by geo lookup) the user has connected from"}],["$","td",null,{"children":["$","code",null,{"children":"CheckImpossibleTravel"}]}]]}],["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"AvgResponseSize"}]}],["$","td",null,{"children":"Average response duration/size across the learning period"}],["$","td",null,{"children":["$","code",null,{"children":"CheckDataExfiltration"}]}]]}]]}]]}]
19:["$","p",null,{"children":["The ",["$","code",null,{"children":"LearningPeriod"}]," determines the time window for baseline computation. The default is 7 days. A longer period (e.g., 14 or 30 days) produces more stable baselines but adapts more slowly to legitimate changes in user behavior."]}]
1a:["$","$L2",null,{"language":"go","showLineNumbers":false,"code":"// Short learning period — adapts quickly, less stable\nLearningPeriod: 3 * 24 * time.Hour,  // 3 days\n\n// Default — balanced\nLearningPeriod: 7 * 24 * time.Hour,  // 7 days\n\n// Long learning period — very stable, slow to adapt\nLearningPeriod: 30 * 24 * time.Hour, // 30 days"}]
1b:["$","h2",null,{"id":"events","children":"Anomaly Events"}]
1c:["$","p",null,{"children":["When an anomaly is detected, Sentinel emits a ",["$","code",null,{"children":"ThreatEvent"}]," with the threat type"," ",["$","code",null,{"children":"AnomalyDetected"}],". These events appear in the dashboard alongside WAF detections and other security events."]}]
1d:["$","table",null,{"children":[["$","thead",null,{"children":["$","tr",null,{"children":[["$","th",null,{"children":"Event Field"}],["$","th",null,{"children":"Value"}]]}]}],["$","tbody",null,{"children":[["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"ThreatTypes"}]}],["$","td",null,{"children":["$","code",null,{"children":"[\"AnomalyDetected\"]"}]}]]}],["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"Severity"}]}],["$","td",null,{"children":"Computed from the anomaly score: Critical (≥80), High (≥60), Medium (≥30), Low (<30)"}]]}],["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"Confidence"}]}],["$","td",null,{"children":"The raw anomaly score (0-100), representing how far the activity deviates from baseline"}]]}],["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"Evidence"}]}],["$","td",null,{"children":"Contains the anomaly score and the list of checks that contributed to it"}]]}],["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"Blocked"}]}],["$","td",null,{"children":[["$","code",null,{"children":"false"}]," — anomaly events are informational; they do not block requests"]}]]}]]}]]}]
1e:["$","h3",null,{"children":"Severity Mapping"}]
1f:["$","p",null,{"children":"The anomaly score is mapped to a severity level using the following thresholds:"}]
20:["$","table",null,{"children":[["$","thead",null,{"children":["$","tr",null,{"children":[["$","th",null,{"children":"Score Range"}],["$","th",null,{"children":"Severity"}],["$","th",null,{"children":"Interpretation"}]]}]}],["$","tbody",null,{"children":[["$","tr",null,{"children":[["$","td",null,{"children":"80 - 100"}],["$","td",null,{"children":["$","code",null,{"children":"Critical"}]}],["$","td",null,{"children":"Multiple strong anomaly signals. Very likely a compromised account or active attack."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":"60 - 79"}],["$","td",null,{"children":["$","code",null,{"children":"High"}]}],["$","td",null,{"children":"Significant deviation from baseline. Warrants immediate investigation."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":"30 - 59"}],["$","td",null,{"children":["$","code",null,{"children":"Medium"}]}],["$","td",null,{"children":"Moderate deviation. Could be a legitimate change in behavior or early sign of compromise."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":"0 - 29"}],["$","td",null,{"children":["$","code",null,{"children":"Low"}]}],["$","td",null,{"children":"Minor deviation. Usually benign but logged for audit purposes."}]]}]]}]]}]
21:["$","div",null,{"className":"my-4 rounded-lg border p-4 bg-blue-50 dark:bg-blue-950/30 border-blue-200 dark:border-blue-800","children":["$","div",null,{"className":"flex items-start gap-3","children":[["$","svg",null,{"xmlns":"http://www.w3.org/2000/svg","width":18,"height":18,"viewBox":"0 0 24 24","fill":"none","stroke":"currentColor","strokeWidth":2,"strokeLinecap":"round","strokeLinejoin":"round","className":"lucide lucide-info mt-0.5 flex-shrink-0 text-blue-500","children":[["$","circle","1mglay",{"cx":"12","cy":"12","r":"10"}],["$","path","1dtifu",{"d":"M12 16v-4"}],["$","path","e9boi3",{"d":"M12 8h.01"}],"$undefined"]}],["$","div",null,{"children":[["$","p",null,{"className":"font-semibold text-sm mb-1 text-blue-800 dark:text-blue-300","children":"Anomaly Events Are Non-Blocking"}],["$","div",null,{"className":"text-sm text-gray-700 dark:text-gray-300","children":["Anomaly events are always informational — they never block requests. The detector flags suspicious behavior so you can investigate, but it does not interrupt user sessions. To automatically respond to anomalies, pair anomaly detection with the"," ",["$","a",null,{"href":"/docs/alerting","children":"alerting system"}]," to receive notifications when high-severity anomalies occur."]}]]}]]}]}]
22:["$","h2",null,{"id":"full-example","children":"Full Configuration Example"}]
23:["$","p",null,{"children":"Below is a complete example that enables anomaly detection alongside other Sentinel features:"}]
36:T6b2,package main

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
}24:["$","$L2",null,{"language":"go","filename":"main.go","code":"$36"}]
25:["$","h2",null,{"id":"testing","children":"Testing Considerations"}]
26:["$","p",null,{"children":"Anomaly detection requires sufficient historical data to produce meaningful baselines. This makes it harder to test than the WAF or rate limiter, which respond immediately. Here are strategies for testing effectively."}]
27:["$","h3",null,{"children":"Building a Baseline"}]
28:["$","p",null,{"children":"The detector requires at least 10 activity records for a user before it will evaluate checks. In a test environment, you can seed activity data by sending authenticated requests over a consistent pattern, then introducing an anomalous request to verify detection."}]
29:["$","$L2",null,{"language":"bash","showLineNumbers":false,"code":"# Seed baseline activity (repeat over multiple hours/days for a realistic baseline)\nfor i in $(seq 1 20); do\n    curl -s -H \"X-User-ID: testuser\" http://localhost:8080/api/data > /dev/null\n    sleep 1\ndone\n\n# Now trigger an anomaly — access from a different IP or unusual route\ncurl -s -H \"X-User-ID: testuser\" http://localhost:8080/admin/settings\n# Check the Sentinel dashboard for an AnomalyDetected event"}]
2a:["$","h3",null,{"children":"Shorter Learning Period for Tests"}]
2b:["$","p",null,{"children":["Use a short ",["$","code",null,{"children":"LearningPeriod"}]," in test environments so baselines are computed from a smaller window of data:"]}]
2c:["$","$L2",null,{"language":"go","showLineNumbers":false,"code":"// In tests, use a short learning period\nAnomaly: sentinel.AnomalyConfig{\n    Enabled:        true,\n    Sensitivity:    sentinel.AnomalySensitivityHigh, // Catch everything\n    LearningPeriod: 1 * time.Hour,                  // Short window for tests\n}"}]
2d:["$","h3",null,{"children":"Unit Testing"}]
2e:["$","p",null,{"children":["You can test the anomaly detector programmatically by creating a store, seeding activity data, and calling ",["$","code",null,{"children":"CheckActivity"}]," directly:"]}]
37:T744,func TestAnomalyDetection(t *testing.T) {
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
}2f:["$","$L2",null,{"language":"go","filename":"anomaly_test.go","code":"$37"}]
30:["$","div",null,{"className":"my-4 rounded-lg border p-4 bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-800","children":["$","div",null,{"className":"flex items-start gap-3","children":[["$","svg",null,{"xmlns":"http://www.w3.org/2000/svg","width":18,"height":18,"viewBox":"0 0 24 24","fill":"none","stroke":"currentColor","strokeWidth":2,"strokeLinecap":"round","strokeLinejoin":"round","className":"lucide lucide-triangle-alert mt-0.5 flex-shrink-0 text-amber-500","children":[["$","path","wmoenq",{"d":"m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"}],["$","path","juzpu7",{"d":"M12 9v4"}],["$","path","p32p05",{"d":"M12 17h.01"}],"$undefined"]}],["$","div",null,{"children":[["$","p",null,{"className":"font-semibold text-sm mb-1 text-amber-800 dark:text-amber-300","children":"Timing in Tests"}],["$","div",null,{"className":"text-sm text-gray-700 dark:text-gray-300","children":["The anomaly detector emits threat events asynchronously through the pipeline. In unit tests, add a short ",["$","code",null,{"children":"time.Sleep"}]," (e.g., 100ms) after calling ",["$","code",null,{"children":"CheckActivity"}]," ","to allow the pipeline to process the event before asserting on results."]}]]}]]}]}]
31:["$","h2",null,{"children":"Next Steps"}]
32:["$","ul",null,{"children":[["$","li",null,{"children":[["$","a",null,{"href":"/docs/configuration","children":"Configuration Reference"}]," — Full AnomalyConfig field reference"]}],["$","li",null,{"children":[["$","a",null,{"href":"/docs/auth-shield","children":"Auth Shield"}]," — Brute-force and credential stuffing protection"]}],["$","li",null,{"children":[["$","a",null,{"href":"/docs/waf","children":"WAF"}]," — Signature-based attack detection to complement anomaly detection"]}],["$","li",null,{"children":[["$","a",null,{"href":"/docs/alerting","children":"Alerting"}]," — Get notified when anomalies are detected"]}],["$","li",null,{"children":[["$","a",null,{"href":"/docs/the-dashboard","children":"Dashboard"}]," — View anomaly events and user baselines"]}]]}]
33:["$","script","script-0",{"src":"/_next/static/chunks/2425b678dfc0c3cf.js","async":true}]
34:["$","$L38",null,{"children":["$","$39",null,{"name":"Next.MetadataOutlet","children":"$@3a"}]}]
3a:null
