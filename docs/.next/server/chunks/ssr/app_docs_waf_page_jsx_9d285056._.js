module.exports=[58769,a=>{"use strict";var b=a.i(81332),c=a.i(17924),d=a.i(64939);function e(){return(0,b.jsxs)(b.Fragment,{children:[(0,b.jsx)("h1",{children:"Web Application Firewall (WAF)"}),(0,b.jsxs)("p",{children:["Sentinel includes a built-in Web Application Firewall that inspects every incoming HTTP request for malicious payloads. It provides comprehensive coverage for the"," ",(0,b.jsx)("strong",{children:"OWASP Top 10"})," attack categories, including SQL injection, cross-site scripting (XSS), path traversal, command injection, server-side request forgery (SSRF), XML external entity injection (XXE), local file inclusion (LFI), and open redirect attacks."]}),(0,b.jsxs)("p",{children:["The WAF operates as Gin middleware registered by ",(0,b.jsx)("code",{children:"sentinel.Mount()"}),". It runs before your application handlers, so malicious requests are intercepted before they reach your business logic. All detections are recorded as security events and are visible in the Sentinel dashboard."]}),(0,b.jsxs)(d.default,{type:"info",title:"Zero False Positives by Default",children:["Sentinel ships with carefully tuned regex patterns at multiple strictness levels. Start with the defaults, observe traffic in ",(0,b.jsx)("code",{children:"ModeLog"}),", and adjust sensitivity per category as needed for your application."]}),(0,b.jsx)("h2",{id:"enabling",children:"Enabling the WAF"}),(0,b.jsxs)("p",{children:["The WAF is disabled by default. To enable it, set ",(0,b.jsx)("code",{children:"Enabled: true"})," in your"," ",(0,b.jsx)("code",{children:"WAFConfig"})," and choose a mode. The simplest configuration enables blocking mode with all default rule sensitivities:"]}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`package main

import (
    sentinel "github.com/MUKE-coder/sentinel"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

    sentinel.Mount(r, nil, sentinel.Config{
        WAF: sentinel.WAFConfig{
            Enabled: true,
            Mode:    sentinel.ModeBlock,
        },
    })

    r.GET("/api/data", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })

    r.Run(":8080")
}`}),(0,b.jsx)("p",{children:"With this configuration, Sentinel inspects every request against all built-in rule categories at their default strictness levels. Malicious requests receive an HTTP 403 response and are logged as security events."}),(0,b.jsx)("h2",{id:"modes",children:"WAF Modes"}),(0,b.jsx)("p",{children:"The WAF supports two primary operating modes. The mode determines what happens when a malicious payload is detected."}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Mode"}),(0,b.jsx)("th",{children:"Constant"}),(0,b.jsx)("th",{children:"Behavior"}),(0,b.jsx)("th",{children:"Use Case"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Log"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.ModeLog"})}),(0,b.jsxs)("td",{children:["Detects and records threats but ",(0,b.jsx)("strong",{children:"allows the request to proceed"}),". The event is logged and visible in the dashboard."]}),(0,b.jsx)("td",{children:"Initial rollout, testing, auditing"})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Block"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.ModeBlock"})}),(0,b.jsxs)("td",{children:["Detects threats and ",(0,b.jsx)("strong",{children:"rejects the request with HTTP 403 Forbidden"}),". The response includes a JSON body with the block reason."]}),(0,b.jsx)("td",{children:"Production enforcement"})]})]})]}),(0,b.jsx)("h3",{children:"ModeLog (Detect Only)"}),(0,b.jsx)("p",{children:"In log mode, the WAF identifies malicious payloads and creates security events, but it does not block the request. This is ideal for initial deployment when you want to observe what the WAF detects without impacting real traffic."}),(0,b.jsx)(c.default,{language:"go",code:`WAF: sentinel.WAFConfig{
    Enabled: true,
    Mode:    sentinel.ModeLog, // Detect and log, but don't block
}`}),(0,b.jsx)("p",{children:"When a threat is detected in log mode, the request continues to your handler normally. The detection is recorded and appears in the dashboard under the Events page with full details including the matched pattern, severity, and request metadata."}),(0,b.jsx)("h3",{children:"ModeBlock (Block Malicious Requests)"}),(0,b.jsx)("p",{children:"In block mode, detected threats are rejected immediately with an HTTP 403 status code. The request never reaches your application handler. The response body contains a JSON object describing the block:"}),(0,b.jsx)(c.default,{language:"go",code:`WAF: sentinel.WAFConfig{
    Enabled: true,
    Mode:    sentinel.ModeBlock, // Detect and block with 403
}`}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Example blocked response
HTTP/1.1 403 Forbidden
Content-Type: application/json

{
  "error": "Request blocked by WAF",
  "reason": "SQL Injection detected",
  "request_id": "abc123"
}`}),(0,b.jsxs)(d.default,{type:"success",title:"Recommended Rollout Strategy",children:["Start with ",(0,b.jsx)("code",{children:"sentinel.ModeLog"})," in production for 1-2 weeks to observe detections and identify any false positives. Review the dashboard, tune rule sensitivities and exclusions, then switch to ",(0,b.jsx)("code",{children:"sentinel.ModeBlock"})," when you are confident in the configuration."]}),(0,b.jsx)("h2",{id:"built-in-rules",children:"Built-in Rules"}),(0,b.jsx)("p",{children:"Sentinel ships with eight built-in detection rule categories that cover the most common web attack vectors. Each category has its own set of regex patterns and can be independently configured with a strictness level."}),(0,b.jsx)("h3",{children:"Rule Categories"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Category"}),(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"SQL Injection"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"SQLInjection"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RuleStrict"})}),(0,b.jsx)("td",{children:"Detects SQL injection attempts including UNION-based, boolean-based, time-based blind, and error-based injection patterns."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Cross-Site Scripting"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"XSS"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RuleStrict"})}),(0,b.jsxs)("td",{children:["Detects XSS payloads including script tags, event handlers (",(0,b.jsx)("code",{children:"onerror"}),", ",(0,b.jsx)("code",{children:"onload"}),"), ",(0,b.jsx)("code",{children:"javascript:"})," URIs, and encoded variants."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Path Traversal"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"PathTraversal"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RuleStrict"})}),(0,b.jsxs)("td",{children:["Detects directory traversal sequences (",(0,b.jsx)("code",{children:"../"}),", ",(0,b.jsx)("code",{children:"..%2f"}),") targeting sensitive system files like ",(0,b.jsx)("code",{children:"/etc/passwd"})," or ",(0,b.jsx)("code",{children:"web.config"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Command Injection"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CommandInjection"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RuleStrict"})}),(0,b.jsxs)("td",{children:["Detects OS command injection via shell metacharacters (",(0,b.jsx)("code",{children:";"}),", ",(0,b.jsx)("code",{children:"|"}),", ",(0,b.jsx)("code",{children:"&&"}),", backticks) and common commands (",(0,b.jsx)("code",{children:"cat"}),", ",(0,b.jsx)("code",{children:"wget"}),", ",(0,b.jsx)("code",{children:"curl"}),")."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"SSRF"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"SSRF"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RuleMedium"})}),(0,b.jsxs)("td",{children:["Detects server-side request forgery attempts targeting internal networks (",(0,b.jsx)("code",{children:"127.0.0.1"}),", ",(0,b.jsx)("code",{children:"169.254.169.254"}),", ",(0,b.jsx)("code",{children:"localhost"}),", private IP ranges)."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"XXE"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"XXE"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RuleStrict"})}),(0,b.jsxs)("td",{children:["Detects XML external entity injection via ",(0,b.jsx)("code",{children:"DOCTYPE"})," declarations, ",(0,b.jsx)("code",{children:"ENTITY"})," definitions, and ",(0,b.jsx)("code",{children:"SYSTEM"})," identifiers in request bodies."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"LFI"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"LFI"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RuleStrict"})}),(0,b.jsxs)("td",{children:["Detects local file inclusion attempts targeting common sensitive paths (",(0,b.jsx)("code",{children:"/etc/shadow"}),", ",(0,b.jsx)("code",{children:"/proc/self"}),", ",(0,b.jsx)("code",{children:"php://filter"}),")."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Open Redirect"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"OpenRedirect"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RuleMedium"})}),(0,b.jsxs)("td",{children:["Detects open redirect attempts via URL parameters containing external URLs or protocol-relative URLs (",(0,b.jsx)("code",{children:"//evil.com"}),")."]})]})]})]}),(0,b.jsx)("h3",{children:"Strictness Levels"}),(0,b.jsx)("p",{children:"Each rule category supports three strictness levels that control how aggressively patterns are matched. Higher strictness catches more edge cases but may produce more false positives for certain applications."}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Level"}),(0,b.jsx)("th",{children:"Constant"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Off"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.RuleOff"})}),(0,b.jsx)("td",{children:"Completely disables this rule category. No patterns are evaluated."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Basic"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.RuleBasic"})}),(0,b.jsx)("td",{children:"Matches only the most obvious and high-confidence attack patterns. Lowest false positive rate."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Strict"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.RuleStrict"})}),(0,b.jsx)("td",{children:"Matches a comprehensive set of patterns including encoded and obfuscated variants. Highest coverage, but may require exclusions for some applications."})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"config.go",code:`WAF: sentinel.WAFConfig{
    Enabled: true,
    Mode:    sentinel.ModeBlock,
    Rules: sentinel.RuleSet{
        SQLInjection:     sentinel.RuleStrict,  // Maximum SQL injection coverage
        XSS:              sentinel.RuleStrict,  // Maximum XSS coverage
        PathTraversal:    sentinel.RuleStrict,  // Catch encoded traversal sequences
        CommandInjection: sentinel.RuleBasic,   // Basic only — reduces false positives for CLI tools
        SSRF:             sentinel.RuleMedium,  // Balanced SSRF detection
        XXE:              sentinel.RuleStrict,  // Full XXE protection
        LFI:              sentinel.RuleStrict,  // Full LFI protection
        OpenRedirect:     sentinel.RuleOff,     // Disabled — app handles redirects internally
    },
}`}),(0,b.jsxs)(d.default,{type:"warning",title:"Disabling Rules",children:["Setting a rule category to ",(0,b.jsx)("code",{children:"sentinel.RuleOff"})," completely disables that detection class. Only do this if you are certain your application is not vulnerable to that attack vector, or if you have other defenses in place (e.g., a cloud WAF handling that category)."]}),(0,b.jsx)("h2",{id:"custom-rules",children:"Custom Rules"}),(0,b.jsxs)("p",{children:["In addition to the built-in rules, you can define custom rules to detect application-specific attack patterns. Custom rules are defined as ",(0,b.jsx)("code",{children:"WAFRule"})," structs and are evaluated alongside the built-in rules during request inspection."]}),(0,b.jsx)("h3",{children:"WAFRule Struct"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ID"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Unique identifier for the rule. Used in event logs and the dashboard. Must be unique across all custom rules."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Name"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:"Human-readable name displayed in the dashboard and event details."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Pattern"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsxs)("td",{children:["Go-compatible regular expression. Compiled once at startup for performance. Use raw strings (",(0,b.jsx)("code",{children:"`...`"}),") to avoid double-escaping."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"AppliesTo"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"[]string"})}),(0,b.jsxs)("td",{children:["Which parts of the request to inspect. Valid values: ",(0,b.jsx)("code",{children:'"path"'}),", ",(0,b.jsx)("code",{children:'"query"'}),", ",(0,b.jsx)("code",{children:'"headers"'}),", ",(0,b.jsx)("code",{children:'"body"'}),". You can specify multiple."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Severity"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Severity"})}),(0,b.jsxs)("td",{children:["Severity level assigned to matches. Options: ",(0,b.jsx)("code",{children:"sentinel.SeverityLow"}),", ",(0,b.jsx)("code",{children:"sentinel.SeverityMedium"}),", ",(0,b.jsx)("code",{children:"sentinel.SeverityHigh"}),", ",(0,b.jsx)("code",{children:"sentinel.SeverityCritical"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Action"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsxs)("td",{children:["Action to take when the pattern matches: ",(0,b.jsx)("code",{children:'"block"'})," (reject with 403) or ",(0,b.jsx)("code",{children:'"log"'})," (record but allow). This overrides the global WAF mode for this specific rule."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsxs)("td",{children:["Whether the rule is active. Set to ",(0,b.jsx)("code",{children:"false"})," to disable a rule without removing it from the configuration."]})]})]})]}),(0,b.jsx)("h3",{children:"AppliesTo Targets"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Target"}),(0,b.jsx)("th",{children:"What Is Inspected"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:'"path"'})}),(0,b.jsxs)("td",{children:["The URL path (e.g., ",(0,b.jsx)("code",{children:"/api/users/123"}),")"]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:'"query"'})}),(0,b.jsxs)("td",{children:["The raw query string (e.g., ",(0,b.jsx)("code",{children:"id=1&name=test"}),")"]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:'"headers"'})}),(0,b.jsx)("td",{children:"All HTTP request headers concatenated (key: value pairs)"})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:'"body"'})}),(0,b.jsx)("td",{children:"The request body (for POST, PUT, PATCH requests)"})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"config.go",code:`CustomRules: []sentinel.WAFRule{
    {
        ID:        "block-wp-admin",
        Name:      "Block WordPress admin probes",
        Pattern:   \`(?i)/(wp-admin|wp-login\\.php|xmlrpc\\.php|wp-content)\`,
        AppliesTo: []string{"path"},
        Severity:  sentinel.SeverityMedium,
        Action:    "block",
        Enabled:   true,
    },
    {
        ID:        "block-sensitive-files",
        Name:      "Block sensitive file access",
        Pattern:   \`(?i)\\.(env|git|bak|sql|log|ini|cfg|conf|swp)$\`,
        AppliesTo: []string{"path"},
        Severity:  sentinel.SeverityHigh,
        Action:    "block",
        Enabled:   true,
    },
    {
        ID:        "block-scanner-bots",
        Name:      "Block known scanner user agents",
        Pattern:   \`(?i)(sqlmap|nikto|nessus|dirbuster|gobuster|masscan|nmap)\`,
        AppliesTo: []string{"headers"},
        Severity:  sentinel.SeverityHigh,
        Action:    "block",
        Enabled:   true,
    },
    {
        ID:        "log-api-key-exposure",
        Name:      "Detect API key in query string",
        Pattern:   \`(?i)(api[_-]?key|apikey|secret|token|password)=.+\`,
        AppliesTo: []string{"query"},
        Severity:  sentinel.SeverityMedium,
        Action:    "log",
        Enabled:   true,
    },
}`}),(0,b.jsxs)(d.default,{type:"info",title:"Rule Action vs Global Mode",children:["Each custom rule has its own ",(0,b.jsx)("code",{children:"Action"})," field that overrides the global WAF mode for that specific rule. This means you can set the WAF to ",(0,b.jsx)("code",{children:"ModeLog"})," globally but have individual custom rules that block, or vice versa. Built-in rules always follow the global mode."]}),(0,b.jsx)("h2",{id:"exclusions",children:"Excluding Routes and IPs"}),(0,b.jsx)("p",{children:"You can exclude specific routes and IP addresses from WAF inspection. Excluded routes and IPs bypass the WAF entirely — no patterns are evaluated and no events are generated for these requests."}),(0,b.jsx)("h3",{children:"ExcludeRoutes"}),(0,b.jsxs)("p",{children:["Use ",(0,b.jsx)("code",{children:"ExcludeRoutes"})," to skip WAF inspection for specific URL paths. This is commonly used for health check endpoints, metrics endpoints, or routes that legitimately handle content that might trigger WAF rules (e.g., a CMS editor)."]}),(0,b.jsx)(c.default,{language:"go",code:`WAF: sentinel.WAFConfig{
    Enabled: true,
    Mode:    sentinel.ModeBlock,
    ExcludeRoutes: []string{
        "/health",           // Health check endpoint
        "/readiness",        // Kubernetes readiness probe
        "/metrics",          // Prometheus metrics
        "/api/v1/webhooks",  // Incoming webhooks may contain arbitrary content
    },
}`}),(0,b.jsx)("h3",{children:"ExcludeIPs"}),(0,b.jsxs)("p",{children:["Use ",(0,b.jsx)("code",{children:"ExcludeIPs"})," to skip WAF inspection for trusted IP addresses or CIDR ranges. This is useful for internal services, monitoring systems, or CI/CD pipelines that might trigger false positives."]}),(0,b.jsx)(c.default,{language:"go",code:`WAF: sentinel.WAFConfig{
    Enabled: true,
    Mode:    sentinel.ModeBlock,
    ExcludeIPs: []string{
        "127.0.0.1",       // Localhost
        "10.0.0.0/8",      // Internal network
        "172.16.0.0/12",   // Docker networks
        "192.168.0.0/16",  // Private network
        "203.0.113.50",    // Monitoring server
    },
}`}),(0,b.jsxs)(d.default,{type:"warning",title:"Be Careful with IP Exclusions",children:["Excluded IPs bypass all WAF rules including custom rules. Only exclude IPs you fully trust. If an attacker can spoof a trusted IP (e.g., via the ",(0,b.jsx)("code",{children:"X-Forwarded-For"})," header), they could bypass the WAF. Make sure your reverse proxy sets the client IP correctly and that Gin is configured to trust the right proxy headers."]}),(0,b.jsx)("h2",{id:"how-detection-works",children:"How Detection Works"}),(0,b.jsx)("p",{children:"Understanding the WAF detection pipeline helps you configure it effectively and debug false positives."}),(0,b.jsx)("h3",{children:"Request Inspection Flow"}),(0,b.jsxs)("ol",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Exclusion Check"})," — The middleware first checks if the request IP or route is in the exclusion lists. If so, the request is passed through without inspection."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Request Decomposition"})," — The classifier extracts four components from the request: the URL ",(0,b.jsx)("strong",{children:"path"}),", the raw ",(0,b.jsx)("strong",{children:"query string"}),", all HTTP ",(0,b.jsx)("strong",{children:"headers"})," (concatenated), and the request ",(0,b.jsx)("strong",{children:"body"})," (if present)."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Pattern Matching"})," — Each extracted component is evaluated against the compiled regex patterns for all enabled rule categories. The patterns are compiled once at startup for performance. Both built-in rules and custom rules are evaluated."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Threat Event Creation"})," — When a pattern matches, a ",(0,b.jsx)("code",{children:"ThreatEvent"})," is created containing the rule ID, category, severity, matched pattern, the request component that matched, and full request metadata (IP, user agent, timestamp)."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Async Pipeline"})," — The threat event is sent to the async event pipeline via a non-blocking ring buffer. Worker goroutines pick up the event and persist it to storage, update threat actor profiles, recompute security scores, and dispatch alerts if the severity threshold is met."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Response"})," — Based on the WAF mode (or the custom rule action), the request is either blocked with a 403 response or allowed to proceed to the next handler."]})]}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# The detection flow visualized:
#
# Request ──> Exclusion Check ──> Decompose Request ──> Pattern Matching
#                  │                                         │
#                  │ (excluded)                    ┌─────────┴─────────┐
#                  v                               v                   v
#              Pass Through                  No Match              Match Found
#                                               │                     │
#                                               v                     v
#                                          Pass Through         Create ThreatEvent
#                                                                     │
#                                                          ┌──────────┴──────────┐
#                                                          v                      v
#                                                      ModeLog              ModeBlock
#                                                          │                      │
#                                                          v                      v
#                                                   Log + Continue          Log + 403`}),(0,b.jsx)(d.default,{type:"info",title:"Non-Blocking Event Pipeline",children:"The WAF detection and event logging are decoupled. Pattern matching happens synchronously in the request path, but event persistence, threat profiling, score computation, and alerting all happen asynchronously via the pipeline. This means the WAF adds minimal latency to your requests even under heavy attack traffic."}),(0,b.jsx)("h2",{id:"testing",children:"Testing the WAF"}),(0,b.jsx)("p",{children:"After enabling the WAF, you should test it to verify that it correctly detects and handles malicious requests. Below are curl commands you can use to test each major attack category."}),(0,b.jsx)("h3",{children:"Testing SQL Injection"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Classic SQL injection in query parameter
curl -v "http://localhost:8080/api/users?id=1'+OR+'1'='1"

# UNION-based SQL injection
curl -v "http://localhost:8080/api/users?id=1+UNION+SELECT+username,password+FROM+users--"

# Boolean-based blind injection
curl -v "http://localhost:8080/api/users?id=1+AND+1=1"

# SQL injection in POST body
curl -v -X POST http://localhost:8080/api/search \\
  -H "Content-Type: application/json" \\
  -d '{"query": "test\\"; DROP TABLE users; --"}'`}),(0,b.jsx)("h3",{children:"Testing XSS"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Script tag injection
curl -v "http://localhost:8080/api/search?q=<script>alert('xss')</script>"

# Event handler injection
curl -v "http://localhost:8080/api/search?q=<img+src=x+onerror=alert(1)>"

# JavaScript URI
curl -v "http://localhost:8080/api/search?q=javascript:alert(document.cookie)"`}),(0,b.jsx)("h3",{children:"Testing Path Traversal"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Basic path traversal
curl -v "http://localhost:8080/api/files/../../../../etc/passwd"

# URL-encoded traversal
curl -v "http://localhost:8080/api/files/..%2f..%2f..%2fetc%2fpasswd"

# Double-encoded traversal
curl -v "http://localhost:8080/api/files/..%252f..%252f..%252fetc%252fpasswd"`}),(0,b.jsx)("h3",{children:"Testing Command Injection"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Semicolon injection
curl -v "http://localhost:8080/api/ping?host=127.0.0.1;cat+/etc/passwd"

# Pipe injection
curl -v "http://localhost:8080/api/ping?host=127.0.0.1|whoami"

# Backtick injection
curl -v "http://localhost:8080/api/ping?host=\\\`whoami\\\`"`}),(0,b.jsx)("h3",{children:"Expected Responses"}),(0,b.jsx)("p",{children:"The response you receive depends on the WAF mode:"}),(0,b.jsx)("h4",{children:"ModeBlock Response (403 Forbidden)"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`$ curl -s "http://localhost:8080/api/users?id=1'+OR+'1'='1" | jq .
{
  "error": "Request blocked by WAF",
  "reason": "SQL Injection detected",
  "request_id": "req_abc123def456"
}`}),(0,b.jsx)("h4",{children:"ModeLog Response (200 OK, event logged)"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`$ curl -s "http://localhost:8080/api/users?id=1'+OR+'1'='1" | jq .
{
  "users": []
}
# The request succeeds, but a WAF event is logged in the dashboard.
# Check the Sentinel Events page to see the detection.`}),(0,b.jsx)(d.default,{type:"danger",title:"Testing in Production",children:"Only run these tests against development or staging environments. Running attack payloads against a production system could trigger alerts, IP bans, or lock out your own IP address if Auth Shield or IP reputation features are also enabled."}),(0,b.jsx)("h2",{id:"custom-rule-examples",children:"Custom Rule Examples"}),(0,b.jsx)("p",{children:"Below are practical custom rule examples for common use cases. These demonstrate the flexibility of the WAF rule engine for application-specific security needs."}),(0,b.jsx)("h3",{children:"Block WordPress and CMS Admin Probes"}),(0,b.jsx)("p",{children:"Bots constantly scan for common CMS admin panels. If your application is not WordPress, block these immediately to reduce noise."}),(0,b.jsx)(c.default,{language:"go",code:`{
    ID:        "block-cms-probes",
    Name:      "Block CMS admin panel probes",
    Pattern:   \`(?i)/(wp-admin|wp-login\\.php|wp-content|wp-includes|xmlrpc\\.php|administrator|phpmyadmin|adminer|cgi-bin)\`,
    AppliesTo: []string{"path"},
    Severity:  sentinel.SeverityMedium,
    Action:    "block",
    Enabled:   true,
}`}),(0,b.jsx)("h3",{children:"Block Sensitive File Extensions"}),(0,b.jsx)("p",{children:"Prevent access to backup files, configuration files, and version control artifacts that should never be served by your application."}),(0,b.jsx)(c.default,{language:"go",code:`{
    ID:        "block-sensitive-extensions",
    Name:      "Block sensitive file extensions",
    Pattern:   \`(?i)\\.(env|git|gitignore|bak|sql|log|ini|cfg|conf|swp|old|orig|dist|save|DS_Store|htaccess|htpasswd)$\`,
    AppliesTo: []string{"path"},
    Severity:  sentinel.SeverityHigh,
    Action:    "block",
    Enabled:   true,
}`}),(0,b.jsx)("h3",{children:"Block Known Scanner User Agents"}),(0,b.jsx)("p",{children:"Automated security scanners identify themselves via their User-Agent header. Block known scanner signatures to reduce noise in your security logs."}),(0,b.jsx)(c.default,{language:"go",code:`{
    ID:        "block-scanner-agents",
    Name:      "Block known vulnerability scanner agents",
    Pattern:   \`(?i)(sqlmap|nikto|nessus|nmap|masscan|dirbuster|gobuster|wfuzz|ffuf|burpsuite|zap|acunetix|qualys|openvas)\`,
    AppliesTo: []string{"headers"},
    Severity:  sentinel.SeverityHigh,
    Action:    "block",
    Enabled:   true,
}`}),(0,b.jsx)("h3",{children:"Detect API Keys in Query Strings"}),(0,b.jsx)("p",{children:"API keys should be sent in headers, not query strings (which appear in logs and browser history). This rule logs a warning when credentials appear in URLs."}),(0,b.jsx)(c.default,{language:"go",code:`{
    ID:        "detect-credentials-in-url",
    Name:      "Detect credentials in query string",
    Pattern:   \`(?i)(api[_-]?key|apikey|secret[_-]?key|access[_-]?token|auth[_-]?token|password|passwd)=[^&]+\`,
    AppliesTo: []string{"query"},
    Severity:  sentinel.SeverityMedium,
    Action:    "log",  // Log only — don't block, just alert
    Enabled:   true,
}`}),(0,b.jsx)("h3",{children:"Full Custom Rules Configuration"}),(0,b.jsx)("p",{children:"Here is a complete example combining multiple custom rules with the built-in rule set:"}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`sentinel.Mount(r, nil, sentinel.Config{
    WAF: sentinel.WAFConfig{
        Enabled: true,
        Mode:    sentinel.ModeBlock,
        Rules: sentinel.RuleSet{
            SQLInjection:     sentinel.RuleStrict,
            XSS:              sentinel.RuleStrict,
            PathTraversal:    sentinel.RuleStrict,
            CommandInjection: sentinel.RuleStrict,
            SSRF:             sentinel.RuleMedium,
            XXE:              sentinel.RuleStrict,
            LFI:              sentinel.RuleStrict,
            OpenRedirect:     sentinel.RuleMedium,
        },
        CustomRules: []sentinel.WAFRule{
            {
                ID:        "block-cms-probes",
                Name:      "Block CMS admin panel probes",
                Pattern:   \`(?i)/(wp-admin|wp-login\\.php|xmlrpc\\.php|phpmyadmin)\`,
                AppliesTo: []string{"path"},
                Severity:  sentinel.SeverityMedium,
                Action:    "block",
                Enabled:   true,
            },
            {
                ID:        "block-sensitive-extensions",
                Name:      "Block sensitive file extensions",
                Pattern:   \`(?i)\\.(env|git|bak|sql|log|swp)$\`,
                AppliesTo: []string{"path"},
                Severity:  sentinel.SeverityHigh,
                Action:    "block",
                Enabled:   true,
            },
            {
                ID:        "block-scanner-agents",
                Name:      "Block scanner user agents",
                Pattern:   \`(?i)(sqlmap|nikto|nessus|dirbuster|gobuster|nmap)\`,
                AppliesTo: []string{"headers"},
                Severity:  sentinel.SeverityHigh,
                Action:    "block",
                Enabled:   true,
            },
            {
                ID:        "detect-credentials-in-url",
                Name:      "Detect credentials in query string",
                Pattern:   \`(?i)(api[_-]?key|secret|token|password)=[^&]+\`,
                AppliesTo: []string{"query"},
                Severity:  sentinel.SeverityMedium,
                Action:    "log",
                Enabled:   true,
            },
        },
        ExcludeRoutes: []string{"/health", "/readiness", "/metrics"},
        ExcludeIPs:    []string{"10.0.0.0/8", "172.16.0.0/12"},
    },
})`}),(0,b.jsx)("h2",{id:"dashboard",children:"WAF Dashboard"}),(0,b.jsx)("p",{children:"The Sentinel dashboard includes a dedicated WAF page that provides a visual interface for managing and monitoring the Web Application Firewall."}),(0,b.jsx)("h3",{children:"Dashboard Capabilities"}),(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Rule Management"})," — View all active built-in and custom rules. Enable or disable individual rules, and adjust strictness levels without restarting the application."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Live Input Testing"})," — Test arbitrary input strings against the active rule set directly from the dashboard. The tester shows which rules would match, the severity, and what action would be taken."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Detection Statistics"})," — View real-time stats on total detections, detections by category, top blocked IPs, most targeted routes, and detection trends over time."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Event Log"})," — Browse all WAF events with filtering by category, severity, IP, time range, and rule ID. Each event shows the full request details and matched pattern."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Custom Rule Editor"})," — Create, edit, and test custom rules directly from the dashboard UI without modifying Go code."]})]}),(0,b.jsxs)("p",{children:["Access the WAF dashboard page at"," ",(0,b.jsx)("code",{children:"http://localhost:8080/sentinel/ui"})," and navigate to the WAF section."]}),(0,b.jsx)(d.default,{type:"info",title:"Dashboard Rule Changes",children:"Rules created or modified via the dashboard are persisted to storage and take effect immediately. They are evaluated alongside rules defined in your Go configuration. If you restart the application, rules from the Go config are always re-applied, while dashboard-created rules are loaded from storage."}),(0,b.jsx)("h2",{children:"Next Steps"}),(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/rate-limiting",children:"Rate Limiting"})," — Layer rate limiting on top of WAF protection"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/auth-shield",children:"Auth Shield"})," — Protect authentication endpoints from brute force attacks"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/anomaly-detection",children:"Anomaly Detection"})," — Add behavioral analysis for advanced threat detection"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/alerting",children:"Alerting"})," — Get notified when the WAF detects high-severity threats"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/the-dashboard",children:"Dashboard"})," — Explore the full security dashboard"]})]})]})}a.s(["default",()=>e,"metadata",0,{title:"WAF - Sentinel Docs"}])}];

//# sourceMappingURL=app_docs_waf_page_jsx_9d285056._.js.map