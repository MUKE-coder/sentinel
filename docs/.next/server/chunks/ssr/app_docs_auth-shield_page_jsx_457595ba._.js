module.exports=[12669,a=>{"use strict";var b=a.i(81332),c=a.i(17924),d=a.i(64939);function e(){return(0,b.jsxs)(b.Fragment,{children:[(0,b.jsx)("h1",{children:"Auth Shield"}),(0,b.jsx)("p",{children:"Auth Shield protects your login endpoints from brute-force attacks and credential stuffing. When enabled, it monitors authentication attempts per IP, automatically locks out offending clients after repeated failures, and emits threat events into the Sentinel pipeline."}),(0,b.jsxs)(d.default,{type:"info",title:"How It Differs from Rate Limiting",children:["Rate limiting controls overall request volume. Auth Shield is purpose-built for login endpoints — it tracks ",(0,b.jsx)("strong",{children:"failed authentication outcomes"})," (non-2xx responses), not just request counts. A legitimate user who logs in successfully on the first try is never affected."]}),(0,b.jsx)("h2",{id:"configuration",children:"Configuration"}),(0,b.jsxs)("p",{children:["Auth Shield is configured through the ",(0,b.jsx)("code",{children:"AuthShieldConfig"})," section of"," ",(0,b.jsx)("code",{children:"sentinel.Config"}),". All fields have sensible defaults except"," ",(0,b.jsx)("code",{children:"LoginRoute"}),", which must match your actual login endpoint path."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsx)("td",{children:"Enables the Auth Shield middleware."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"LoginRoute"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"string"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:'""'})}),(0,b.jsxs)("td",{children:["The exact path of your login endpoint (e.g., ",(0,b.jsx)("code",{children:"/api/login"}),"). Must match the route registered in Gin."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"MaxFailedAttempts"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"int"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"5"})}),(0,b.jsx)("td",{children:"Number of failed login attempts within the lockout window before the IP is locked out."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"LockoutDuration"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"time.Duration"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"15 * time.Minute"})}),(0,b.jsxs)("td",{children:["How long an IP remains locked out after exceeding ",(0,b.jsx)("code",{children:"MaxFailedAttempts"}),". Also used as the sliding window for counting failures."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CredentialStuffingDetection"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsx)("td",{children:"When enabled, detects a single IP trying many different usernames (more than 10 unique usernames within the window)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"BruteForceDetection"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsx)("td",{children:"When enabled, detects repeated password guessing against the same username."})]})]})]}),(0,b.jsx)("h2",{id:"how-it-works",children:"How It Works"}),(0,b.jsxs)("p",{children:["Auth Shield registers as Gin middleware and intercepts only ",(0,b.jsx)("code",{children:"POST"})," requests to the configured ",(0,b.jsx)("code",{children:"LoginRoute"}),". All other routes and HTTP methods pass through untouched. The flow is:"]}),(0,b.jsxs)("ol",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Pre-check"})," — Before your login handler runs, Auth Shield checks if the client IP is currently locked out. If it is, the request is immediately rejected with a ",(0,b.jsx)("code",{children:"429 Too Many Requests"})," response."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Passthrough"})," — If the IP is not locked, the request proceeds to your login handler as normal."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Observe response"})," — After your handler responds, Auth Shield inspects the HTTP status code:",(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"2xx"})," — Successful login. The failure counter for that IP (and username, if provided) is reset to zero."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"4xx"})," — Failed login. The failure is recorded with a timestamp."]})]})]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Lockout"})," — If the number of failures from an IP within the"," ",(0,b.jsx)("code",{children:"LockoutDuration"})," window reaches ",(0,b.jsx)("code",{children:"MaxFailedAttempts"}),", the IP is locked out for the full ",(0,b.jsx)("code",{children:"LockoutDuration"}),"."]})]}),(0,b.jsxs)(d.default,{type:"warning",title:"LoginRoute Must Match Exactly",children:["The ",(0,b.jsx)("code",{children:"LoginRoute"})," must be the exact path string of your login handler (e.g.,"," ",(0,b.jsx)("code",{children:"/api/login"}),"). It is compared against ",(0,b.jsx)("code",{children:"c.Request.URL.Path"}),". If it does not match, Auth Shield will not intercept the request and no failures will be tracked."]}),(0,b.jsx)("h2",{id:"example",children:"Example Configuration"}),(0,b.jsx)("p",{children:"A typical production setup with 5 allowed attempts and a 15-minute lockout:"}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`package main

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
}`}),(0,b.jsxs)(d.default,{type:"info",title:"Username Tracking",children:["To enable per-username failure tracking and credential stuffing detection, set"," ",(0,b.jsx)("code",{children:'c.Set("sentinel_username", username)'})," in your login handler before writing the response. Auth Shield reads this value from the Gin context. If not set, only IP-based tracking is used."]}),(0,b.jsx)("h2",{id:"tracking",children:"What Gets Tracked"}),(0,b.jsx)("p",{children:"Auth Shield determines success or failure based on the HTTP status code returned by your login handler:"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Status Code"}),(0,b.jsx)("th",{children:"Interpretation"}),(0,b.jsx)("th",{children:"Action"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"200-299"})}),(0,b.jsx)("td",{children:"Successful login"}),(0,b.jsx)("td",{children:"Reset all failure counters for the IP and username."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"400-499"})}),(0,b.jsx)("td",{children:"Failed login"}),(0,b.jsxs)("td",{children:["Increment the failure counter. Lock the IP if ",(0,b.jsx)("code",{children:"MaxFailedAttempts"})," is reached."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"500+"})}),(0,b.jsx)("td",{children:"Server error"}),(0,b.jsx)("td",{children:"Ignored. Server errors are not counted as failed login attempts."})]})]})]}),(0,b.jsxs)("p",{children:["Failure timestamps older than ",(0,b.jsx)("code",{children:"LockoutDuration"})," are automatically pruned from the sliding window, so a slow trickle of failures over a long period will not trigger a lockout."]}),(0,b.jsxs)(d.default,{type:"success",title:"Design Your Login Handler Accordingly",children:["Return a ",(0,b.jsx)("code",{children:"401"})," for invalid credentials and a ",(0,b.jsx)("code",{children:"200"})," for successful logins. Avoid returning ",(0,b.jsx)("code",{children:"200"})," with an error in the body, as Auth Shield will treat it as a success and reset the counter."]}),(0,b.jsx)("h2",{id:"lockout-response",children:"Lockout Response"}),(0,b.jsx)("p",{children:"When a locked-out IP attempts to access the login route, Auth Shield returns the following response without invoking your login handler:"}),(0,b.jsx)(c.default,{language:"json",filename:"429 Too Many Requests",showLineNumbers:!1,code:`{
  "error": "Too many failed login attempts. Please try again later.",
  "code": "AUTH_SHIELD_LOCKED"
}`}),(0,b.jsx)("h2",{id:"events",children:"Events"}),(0,b.jsx)("p",{children:"Auth Shield emits threat events into the Sentinel pipeline whenever a lockout is triggered or credential stuffing is detected. These events flow through the same pipeline as WAF and anomaly events, meaning they are:"}),(0,b.jsxs)("ul",{children:[(0,b.jsx)("li",{children:"Stored in the configured storage backend"}),(0,b.jsx)("li",{children:"Visible in the dashboard Threats page"}),(0,b.jsx)("li",{children:"Eligible for alerting (Slack, email, webhook) based on severity"}),(0,b.jsx)("li",{children:"Available for AI analysis if an AI provider is configured"})]}),(0,b.jsx)("h3",{children:"Threat Event Types"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Threat Type"}),(0,b.jsx)("th",{children:"Trigger"}),(0,b.jsx)("th",{children:"Severity"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"BruteForce"})}),(0,b.jsxs)("td",{children:["IP locked out after exceeding ",(0,b.jsx)("code",{children:"MaxFailedAttempts"})]}),(0,b.jsx)("td",{children:"High"})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"CredentialStuffing"})}),(0,b.jsx)("td",{children:"Single IP tries more than 10 different usernames within the window"}),(0,b.jsx)("td",{children:"High"})]})]})]}),(0,b.jsx)("p",{children:"Each event includes the offending IP, the login route path, a confidence score of 90, and evidence detailing the specific detection pattern."}),(0,b.jsx)("h2",{id:"testing",children:"Testing"}),(0,b.jsx)("p",{children:"You can verify Auth Shield is working by sending failed login requests and observing the lockout behavior. The following example assumes the default configuration with 5 max attempts."}),(0,b.jsx)("h3",{children:"Trigger a Lockout"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Send 5 failed login attempts (invalid credentials)
for i in $(seq 1 5); do
  echo "Attempt $i:"
  curl -s -o /dev/null -w "HTTP %{http_code}" \\
    -X POST http://localhost:8080/api/login \\
    -d "username=admin&password=wrong"
  echo ""
done

# Attempt 1-5: HTTP 401 (failed login, counter incrementing)
# After 5 failures, the IP is now locked out.`}),(0,b.jsx)("h3",{children:"Verify the Lockout"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# The 6th attempt should return 429 (locked out)
curl -s -w "\\nHTTP %{http_code}\\n" \\
  -X POST http://localhost:8080/api/login \\
  -d "username=admin&password=wrong"

# Expected output:
# {"error":"Too many failed login attempts. Please try again later.","code":"AUTH_SHIELD_LOCKED"}
# HTTP 429`}),(0,b.jsx)("h3",{children:"Verify Successful Login Still Works (from a different IP)"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Even correct credentials from the locked IP are rejected
curl -s -w "\\nHTTP %{http_code}\\n" \\
  -X POST http://localhost:8080/api/login \\
  -d "username=admin&password=correct-password"

# HTTP 429 (still locked — must wait for LockoutDuration to expire)`}),(0,b.jsxs)(d.default,{type:"warning",title:"Testing Locally",children:["When testing locally, all requests come from ",(0,b.jsx)("code",{children:"127.0.0.1"})," or ",(0,b.jsx)("code",{children:"::1"}),", so they share a single IP counter. To test with different IPs, use the"," ",(0,b.jsx)("code",{children:"X-Forwarded-For"})," header if your setup supports it, or test from different machines."]}),(0,b.jsx)("h2",{id:"dashboard",children:"Dashboard"}),(0,b.jsxs)("p",{children:["Auth Shield events appear in the Sentinel dashboard on the ",(0,b.jsx)("strong",{children:"Threats"})," page. Each event includes:"]}),(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:["Threat type displayed as ",(0,b.jsx)("code",{children:"BruteForce"})," or ",(0,b.jsx)("code",{children:"CredentialStuffing"})]}),(0,b.jsx)("li",{children:"The offending IP address"}),(0,b.jsx)("li",{children:"Timestamp of when the lockout was triggered"}),(0,b.jsx)("li",{children:"Severity level (High)"}),(0,b.jsxs)("li",{children:["Evidence showing the detection pattern and location (",(0,b.jsx)("code",{children:"auth_shield"}),")"]})]}),(0,b.jsxs)("p",{children:["You can filter the Threats page by type to isolate brute-force and credential stuffing events. If alerting is configured with a minimum severity of ",(0,b.jsx)("code",{children:"High"})," or lower, these events will also trigger Slack, email, or webhook notifications."]}),(0,b.jsx)("h2",{id:"combining",children:"Combining with Rate Limiting"}),(0,b.jsx)("p",{children:"Auth Shield and rate limiting are complementary. A recommended pattern is to use both:"}),(0,b.jsx)(c.default,{language:"go",filename:"config.go",code:`sentinel.Config{
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
}`}),(0,b.jsx)("p",{children:"In this setup, rate limiting prevents any IP from making more than 10 requests to the login route in 15 minutes (regardless of success or failure), while Auth Shield specifically tracks authentication failures and locks out after 5 failed attempts."}),(0,b.jsx)("h2",{children:"Next Steps"}),(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/configuration",children:"Configuration Reference"})," — Full list of all configuration options"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/rate-limiting",children:"Rate Limiting"})," — Per-IP, per-user, and per-route rate limits"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/anomaly-detection",children:"Anomaly Detection"})," — Behavioral analysis including credential stuffing patterns"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/alerting",children:"Alerting"})," — Get notified when brute-force attacks are detected"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/the-dashboard",children:"Dashboard"})," — Explore the Threats page and other security views"]})]})]})}a.s(["default",()=>e,"metadata",0,{title:"Auth Shield - Sentinel Docs"}])}];

//# sourceMappingURL=app_docs_auth-shield_page_jsx_457595ba._.js.map