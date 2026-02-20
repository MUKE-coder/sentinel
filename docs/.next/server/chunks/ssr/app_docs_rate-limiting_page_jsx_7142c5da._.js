module.exports=[50004,a=>{"use strict";var b=a.i(81332),c=a.i(17924),d=a.i(64939);function e(){return(0,b.jsxs)(b.Fragment,{children:[(0,b.jsx)("h1",{children:"Rate Limiting"}),(0,b.jsx)("p",{children:"Sentinel provides multi-dimensional rate limiting with sliding window counters. You can enforce limits per IP address, per authenticated user, per route, and globally — all at the same time. Every dimension is evaluated independently, and a request must pass all applicable limits to be allowed through."}),(0,b.jsxs)(d.default,{type:"info",title:"Opt-In Feature",children:["Rate limiting is disabled by default. Set ",(0,b.jsx)("code",{children:"Enabled: true"})," in your"," ",(0,b.jsx)("code",{children:"RateLimitConfig"})," to activate it. You only need to configure the dimensions you care about — any dimension left as ",(0,b.jsx)("code",{children:"nil"})," is simply skipped."]}),(0,b.jsx)("h2",{id:"enabling",children:"Enabling Rate Limiting"}),(0,b.jsx)("p",{children:"The simplest way to get started is to enable rate limiting with a single per-IP limit. This protects every route in your application from individual clients sending too many requests."}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`import (
    "time"

    sentinel "github.com/MUKE-coder/sentinel"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

    sentinel.Mount(r, nil, sentinel.Config{
        RateLimit: sentinel.RateLimitConfig{
            Enabled: true,
            ByIP:    &sentinel.Limit{Requests: 100, Window: time.Minute},
        },
    })

    r.GET("/api/hello", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "Hello, World!"})
    })

    r.Run(":8080")
}`}),(0,b.jsx)("h2",{id:"dimensions",children:"Rate Limit Dimensions"}),(0,b.jsx)("p",{children:"Sentinel supports four independent rate limit dimensions. You can use any combination of them. Each dimension maintains its own set of counters and is evaluated in a specific order."}),(0,b.jsx)("h3",{children:"The Limit Struct"}),(0,b.jsxs)("p",{children:["Every dimension is configured with the same ",(0,b.jsx)("code",{children:"Limit"})," struct, which defines a maximum number of requests within a time window."]}),(0,b.jsx)(c.default,{language:"go",showLineNumbers:!1,code:`type Limit struct {
    Requests int           // Maximum requests allowed within the window
    Window   time.Duration // Time window (e.g., time.Minute, 15 * time.Minute)
}`}),(0,b.jsxs)("h3",{children:["Per-IP (",(0,b.jsx)("code",{children:"ByIP"}),")"]}),(0,b.jsx)("p",{children:"Each unique client IP address gets its own counter. This is the most common dimension and protects against individual clients overwhelming your server."}),(0,b.jsx)(c.default,{language:"go",showLineNumbers:!1,code:`// 100 requests per minute per IP address
ByIP: &sentinel.Limit{Requests: 100, Window: time.Minute}`}),(0,b.jsxs)("h3",{children:["Per-User (",(0,b.jsx)("code",{children:"ByUser"}),")"]}),(0,b.jsxs)("p",{children:["Each authenticated user gets their own counter, identified by a user ID string. This requires a ",(0,b.jsx)("code",{children:"UserIDExtractor"})," function that extracts the user ID from the request. If the extractor returns an empty string (unauthenticated request), the per-user limit is skipped for that request."]}),(0,b.jsx)(c.default,{language:"go",showLineNumbers:!1,code:`// 500 requests per minute per authenticated user
ByUser: &sentinel.Limit{Requests: 500, Window: time.Minute},

// Tell Sentinel how to identify the user
UserIDExtractor: func(c *gin.Context) string {
    return c.GetHeader("X-User-ID")
},`}),(0,b.jsxs)(d.default,{type:"warning",title:"UserIDExtractor Required",children:["The ",(0,b.jsx)("code",{children:"ByUser"})," limit is only enforced when ",(0,b.jsx)("code",{children:"UserIDExtractor"})," is set. Without it, per-user rate limiting is silently skipped even if ",(0,b.jsx)("code",{children:"ByUser"})," is configured."]}),(0,b.jsxs)("h3",{children:["Per-Route (",(0,b.jsx)("code",{children:"ByRoute"}),")"]}),(0,b.jsxs)("p",{children:["Different routes can have different limits. The ",(0,b.jsx)("code",{children:"ByRoute"})," map keys are exact route paths. Each route limit is tracked per IP address (the counter key is a combination of the route path and the client IP)."]}),(0,b.jsx)(c.default,{language:"go",showLineNumbers:!1,code:`// Strict limits on sensitive endpoints
ByRoute: map[string]sentinel.Limit{
    "/api/login":          {Requests: 5, Window: 15 * time.Minute},
    "/api/register":       {Requests: 3, Window: time.Hour},
    "/api/password-reset": {Requests: 3, Window: time.Hour},
},`}),(0,b.jsx)("h3",{children:"Global"}),(0,b.jsx)("p",{children:"A single counter shared across all requests regardless of source. This is a safety net to protect your application from being overwhelmed by aggregate traffic."}),(0,b.jsx)(c.default,{language:"go",showLineNumbers:!1,code:`// 5000 total requests per minute across all clients
Global: &sentinel.Limit{Requests: 5000, Window: time.Minute}`}),(0,b.jsx)("h3",{children:"All Dimensions Together"}),(0,b.jsx)(c.default,{language:"go",filename:"config.go",code:`RateLimit: sentinel.RateLimitConfig{
    Enabled:  true,
    Strategy: sentinel.SlidingWindow,

    // Per-IP: 100 req/min
    ByIP: &sentinel.Limit{Requests: 100, Window: time.Minute},

    // Per-user: 500 req/min (requires UserIDExtractor)
    ByUser: &sentinel.Limit{Requests: 500, Window: time.Minute},

    // Per-route: different limits for sensitive endpoints
    ByRoute: map[string]sentinel.Limit{
        "/api/login":    {Requests: 5, Window: 15 * time.Minute},
        "/api/register": {Requests: 3, Window: time.Hour},
    },

    // Global: 5000 req/min total
    Global: &sentinel.Limit{Requests: 5000, Window: time.Minute},

    // Extract user ID for per-user limiting
    UserIDExtractor: func(c *gin.Context) string {
        return c.GetHeader("X-User-ID")
    },
}`}),(0,b.jsx)("h2",{id:"config-reference",children:"Configuration Reference"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Enabled"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"bool"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"false"})}),(0,b.jsx)("td",{children:"Enables the rate limiting middleware."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Strategy"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RateLimitStrategy"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.SlidingWindow"})}),(0,b.jsxs)("td",{children:["Algorithm used for counting. Options: ",(0,b.jsx)("code",{children:"sentinel.SlidingWindow"}),", ",(0,b.jsx)("code",{children:"sentinel.FixedWindow"}),", ",(0,b.jsx)("code",{children:"sentinel.TokenBucket"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ByIP"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"*Limit"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsx)("td",{children:"Per-IP rate limit. Each unique client IP gets its own counter."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ByUser"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"*Limit"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsxs)("td",{children:["Per-user rate limit. Requires a ",(0,b.jsx)("code",{children:"UserIDExtractor"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ByRoute"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"map[string]Limit"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsx)("td",{children:"Per-route rate limits. Keys are exact route paths."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Global"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"*Limit"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsx)("td",{children:"Global rate limit applied across all requests regardless of source."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"UserIDExtractor"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"func(*gin.Context) string"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"nil"})}),(0,b.jsx)("td",{children:"Function to extract a user ID from the request for per-user limiting."})]})]})]}),(0,b.jsx)("h2",{id:"priority-order",children:"Priority Order"}),(0,b.jsx)("p",{children:"When multiple dimensions are configured, Sentinel evaluates them in a specific order. The request is rejected as soon as any dimension's limit is exceeded — remaining dimensions are not checked."}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Priority"}),(0,b.jsx)("th",{children:"Dimension"}),(0,b.jsx)("th",{children:"Counter Key"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"1 (highest)"})}),(0,b.jsx)("td",{children:"Per-Route"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"route:/path:IP"})}),(0,b.jsxs)("td",{children:["Checked first. Only applies if the request path matches a key in ",(0,b.jsx)("code",{children:"ByRoute"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"2"})}),(0,b.jsx)("td",{children:"Per-IP"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ip:IP"})}),(0,b.jsxs)("td",{children:["Checked second. Applies to every request when ",(0,b.jsx)("code",{children:"ByIP"})," is set."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"3"})}),(0,b.jsx)("td",{children:"Per-User"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"user:userID"})}),(0,b.jsxs)("td",{children:["Checked third. Only applies when ",(0,b.jsx)("code",{children:"ByUser"})," is set and ",(0,b.jsx)("code",{children:"UserIDExtractor"})," returns a non-empty string."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"4 (lowest)"})}),(0,b.jsx)("td",{children:"Global"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"global"})}),(0,b.jsx)("td",{children:"Checked last. A single counter shared across all requests."})]})]})]}),(0,b.jsxs)(d.default,{type:"info",title:"Independent Evaluation",children:["Route limits do not replace IP or user limits — they are additive. A request to"," ",(0,b.jsx)("code",{children:"/api/login"})," is checked against the route limit ",(0,b.jsx)("strong",{children:"and"})," the IP limit ",(0,b.jsx)("strong",{children:"and"})," the user limit ",(0,b.jsx)("strong",{children:"and"})," the global limit (if all are configured). The request must pass every applicable check."]}),(0,b.jsx)("h2",{id:"response-headers",children:"Response Headers"}),(0,b.jsxs)("p",{children:["Sentinel automatically sets standard rate limit headers on responses so clients can self-regulate. When a limit is exceeded, the client receives a"," ",(0,b.jsx)("code",{children:"429 Too Many Requests"})," response with a JSON body."]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Header"}),(0,b.jsx)("th",{children:"Description"}),(0,b.jsx)("th",{children:"Example"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"X-RateLimit-Limit"})}),(0,b.jsx)("td",{children:"The maximum number of requests allowed in the current window."}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"100"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"X-RateLimit-Remaining"})}),(0,b.jsx)("td",{children:"The number of requests remaining in the current window."}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"73"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Retry-After"})}),(0,b.jsx)("td",{children:"Seconds until the rate limit window resets. Only sent when the limit is exceeded (429 response)."}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"60"})})]})]})]}),(0,b.jsxs)("p",{children:["On a successful request, the response includes ",(0,b.jsx)("code",{children:"X-RateLimit-Limit"})," and"," ",(0,b.jsx)("code",{children:"X-RateLimit-Remaining"})," based on the per-IP limit. When a limit is exceeded, the response body is:"]}),(0,b.jsx)(c.default,{language:"json",showLineNumbers:!1,code:`{
    "error": "Rate limit exceeded",
    "code": "RATE_LIMITED"
}`}),(0,b.jsx)("h2",{id:"per-route-limits",children:"Per-Route Limits"}),(0,b.jsx)("p",{children:"Per-route limits let you apply different thresholds to different endpoints. This is especially useful for protecting sensitive routes like login, registration, and password reset endpoints with much stricter limits than the rest of your API."}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`sentinel.Mount(r, nil, sentinel.Config{
    RateLimit: sentinel.RateLimitConfig{
        Enabled: true,

        // General API limit: 100 req/min per IP
        ByIP: &sentinel.Limit{Requests: 100, Window: time.Minute},

        // Strict limits on sensitive routes
        ByRoute: map[string]sentinel.Limit{
            // Login: 5 attempts per 15 minutes per IP
            "/api/login": {Requests: 5, Window: 15 * time.Minute},

            // Registration: 3 per hour per IP
            "/api/register": {Requests: 3, Window: time.Hour},

            // Password reset: 3 per hour per IP
            "/api/password-reset": {Requests: 3, Window: time.Hour},

            // File upload: 10 per minute per IP
            "/api/upload": {Requests: 10, Window: time.Minute},
        },
    },
})`}),(0,b.jsxs)("p",{children:["Route limits are keyed by the combination of the route path and the client IP. For example, a request to ",(0,b.jsx)("code",{children:"/api/login"})," from IP ",(0,b.jsx)("code",{children:"1.2.3.4"})," uses the counter key"," ",(0,b.jsx)("code",{children:"route:/api/login:1.2.3.4"}),". This means each IP gets its own counter for each route-limited path."]}),(0,b.jsxs)(d.default,{type:"info",title:"Exact Path Matching",children:["Route keys must be exact paths. The path ",(0,b.jsx)("code",{children:"/api/login"})," will not match"," ",(0,b.jsx)("code",{children:"/api/login/"})," (trailing slash) or ",(0,b.jsx)("code",{children:"/api/login?foo=bar"})," (query parameters are stripped). Use the path as it appears in your Gin route definitions."]}),(0,b.jsx)("h2",{id:"how-it-works",children:"How It Works"}),(0,b.jsx)("p",{children:"Sentinel uses sliding window counters stored entirely in memory. Each counter tracks a request count and a window expiration timestamp."}),(0,b.jsxs)("ol",{children:[(0,b.jsxs)("li",{children:["When a request arrives, Sentinel looks up the counter for the relevant key (e.g.,"," ",(0,b.jsx)("code",{children:"ip:1.2.3.4"}),")."]}),(0,b.jsxs)("li",{children:["If no counter exists, or the current time is past the window expiration, a new counter is created with a count of 1 and a window end of ",(0,b.jsx)("code",{children:"now + Window"}),"."]}),(0,b.jsx)("li",{children:"If the counter exists and the window has not expired, the count is incremented."}),(0,b.jsxs)("li",{children:["If the count exceeds the configured limit, the request is rejected with a"," ",(0,b.jsx)("code",{children:"429"})," status."]})]}),(0,b.jsxs)("p",{children:["A background goroutine runs every ",(0,b.jsx)("strong",{children:"30 seconds"})," to clean up expired counters, preventing unbounded memory growth. The cleanup removes any counter whose window has passed."]}),(0,b.jsx)(c.default,{language:"go",showLineNumbers:!1,code:`// Internal counter structure (simplified)
type rateLimitEntry struct {
    count     int       // Number of requests in the current window
    windowEnd time.Time // When the current window expires
}

// Cleanup runs every 30 seconds, removing expired entries
func (rl *RateLimiter) cleanup() {
    ticker := time.NewTicker(30 * time.Second)
    for range ticker.C {
        now := time.Now()
        for key, entry := range rl.counters {
            if now.After(entry.windowEnd) {
                delete(rl.counters, key)
            }
        }
    }
}`}),(0,b.jsx)(d.default,{type:"info",title:"Thread Safety",children:"All counter operations are protected by a read-write mutex. Reads (checking remaining counts) use a read lock for concurrency, while writes (incrementing, cleanup) use an exclusive write lock."}),(0,b.jsx)("h2",{id:"dashboard",children:"Dashboard Management"}),(0,b.jsxs)("p",{children:["The Sentinel dashboard includes a dedicated ",(0,b.jsx)("strong",{children:"Rate Limits"})," page that gives you real-time visibility into your rate limit counters and configuration."]}),(0,b.jsx)("h3",{children:"Live Counter States"}),(0,b.jsx)("p",{children:"The dashboard displays all active rate limit counters in real time. Each entry shows the counter key, the current request count, the window expiration time, and how many requests remain. Counters are automatically removed from the view when their window expires."}),(0,b.jsx)("h3",{children:"Edit Per-Route Limits"}),(0,b.jsx)("p",{children:"You can edit per-route limits directly from the dashboard without restarting your application. This is useful for responding to traffic spikes or adjusting thresholds after observing real-world patterns."}),(0,b.jsx)("h3",{children:"Reset Individual Counters"}),(0,b.jsx)("p",{children:"If a legitimate client gets rate-limited (e.g., during testing or after a deployment), you can reset their counter from the dashboard. This removes the specific counter key, allowing the client to send requests again immediately."}),(0,b.jsx)(d.default,{type:"success",title:"No Restart Required",children:"Changes made through the dashboard (editing route limits, resetting counters) take effect immediately. There is no need to restart or redeploy your application."}),(0,b.jsx)("h2",{id:"testing",children:"Testing"}),(0,b.jsxs)("p",{children:["You can verify rate limiting is working by sending rapid requests with ",(0,b.jsx)("code",{children:"curl"})," and inspecting the response headers."]}),(0,b.jsx)("h3",{children:"Check Rate Limit Headers"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Send a request and inspect rate limit headers
curl -v http://localhost:8080/api/hello 2>&1 | grep -i "x-ratelimit\\|retry-after"

# Expected output (first request):
# < X-RateLimit-Limit: 100
# < X-RateLimit-Remaining: 99`}),(0,b.jsx)("h3",{children:"Hit the Rate Limit"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Send requests in a tight loop to trigger the limit
# (adjust the count based on your configured limit)
for i in $(seq 1 110); do
    STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:8080/api/hello)
    echo "Request $i: HTTP $STATUS"
done

# You should see HTTP 200 for the first 100 requests,
# then HTTP 429 once the limit is exceeded.`}),(0,b.jsx)("h3",{children:"Test Per-Route Limits"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Test the login endpoint (5 requests per 15 minutes)
for i in $(seq 1 7); do
    RESPONSE=$(curl -s -w "\\nHTTP %{http_code}" \\
        -X POST http://localhost:8080/api/login \\
        -H "Content-Type: application/json" \\
        -d '{"email":"test@example.com","password":"test"}')
    echo "Request $i: $RESPONSE"
done

# Requests 1-5: normal response
# Requests 6-7: HTTP 429 with Retry-After header`}),(0,b.jsx)("h3",{children:"Inspect a 429 Response"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# After exceeding the limit, inspect the full 429 response
curl -v http://localhost:8080/api/hello 2>&1

# Response headers will include:
# < HTTP/1.1 429 Too Many Requests
# < X-RateLimit-Limit: 100
# < X-RateLimit-Remaining: 0
# < Retry-After: 60
#
# Response body:
# {"code":"RATE_LIMITED","error":"Rate limit exceeded"}`}),(0,b.jsx)("h2",{id:"limitations",children:"Limitations"}),(0,b.jsx)("p",{children:"The current rate limiter implementation has a few limitations to be aware of when planning your deployment."}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Limitation"}),(0,b.jsx)("th",{children:"Details"}),(0,b.jsx)("th",{children:"Workaround"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"In-memory only"})}),(0,b.jsx)("td",{children:"All rate limit counters are stored in process memory. Counters are lost when the application restarts."}),(0,b.jsx)("td",{children:"Accept that counters reset on restart. For most use cases, this is acceptable because windows are short (minutes/hours)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"No cross-instance sharing"})}),(0,b.jsxs)("td",{children:["If you run multiple instances of your application behind a load balancer, each instance maintains its own independent counters. A client could effectively get"," ",(0,b.jsx)("code",{children:"N x limit"})," requests across ",(0,b.jsx)("code",{children:"N"})," instances."]}),(0,b.jsx)("td",{children:"Use sticky sessions at the load balancer level, or divide your limits by the number of instances (e.g., set 50 req/min per instance if you have 2 instances and want a 100 req/min effective limit)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"Exact path matching"})}),(0,b.jsx)("td",{children:"Per-route limits use exact string matching on the request path. Patterns, wildcards, and path parameters are not supported."}),(0,b.jsxs)("td",{children:["List each specific path you want to limit in the ",(0,b.jsx)("code",{children:"ByRoute"})," map."]})]})]})]}),(0,b.jsx)(d.default,{type:"warning",title:"Multi-Instance Deployments",children:"If you deploy multiple instances behind a load balancer, be aware that each instance tracks rate limits independently. The effective limit per client is multiplied by the number of instances. Plan your per-instance limits accordingly."}),(0,b.jsx)("h2",{children:"Next Steps"}),(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/configuration#rate-limiting",children:"Full Configuration Reference"})," — All rate limit fields and strategies"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/auth-shield",children:"Auth Shield"})," — Brute-force protection for login endpoints"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/waf",children:"WAF Configuration"})," — Web Application Firewall rules and modes"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/the-dashboard",children:"Dashboard"})," — Explore the Rate Limits page and other dashboard features"]})]})]})}a.s(["default",()=>e,"metadata",0,{title:"Rate Limiting - Sentinel Docs"}])}];

//# sourceMappingURL=app_docs_rate-limiting_page_jsx_7142c5da._.js.map