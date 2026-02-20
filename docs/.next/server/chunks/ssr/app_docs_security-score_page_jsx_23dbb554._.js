module.exports=[74018,a=>{"use strict";var b=a.i(81332),c=a.i(17924),d=a.i(64939);function e(){return(0,b.jsxs)(b.Fragment,{children:[(0,b.jsx)("h1",{children:"Security Score"}),(0,b.jsxs)("p",{children:["The Security Score is a weighted composite metric (0-100) that measures your application's overall security posture at a glance. It aggregates five dimensions of your Sentinel configuration and runtime behavior into a single number, graded from ",(0,b.jsx)("strong",{children:"A"})," (90-100) to ",(0,b.jsx)("strong",{children:"F"})," (below 60). The score updates automatically in the background and surfaces actionable recommendations to improve your defenses."]}),(0,b.jsxs)(d.default,{type:"info",title:"Always Active",children:["The score engine runs automatically once Sentinel is mounted. There is no separate configuration to enable it. It uses the main ",(0,b.jsx)("code",{children:"Config"})," you pass to"," ",(0,b.jsx)("code",{children:"sentinel.Mount"})," to evaluate which features are active and how well they are configured."]}),(0,b.jsx)("h2",{id:"dimensions",children:"Score Dimensions"}),(0,b.jsx)("p",{children:"The overall score is a weighted sum of five sub-scores. Each dimension evaluates a different aspect of your security posture:"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Dimension"}),(0,b.jsx)("th",{children:"Weight"}),(0,b.jsx)("th",{children:"What It Measures"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"Threat Activity"})}),(0,b.jsx)("td",{children:"30%"}),(0,b.jsx)("td",{children:"How many threats were detected in the last 24 hours and how severe they are. Fewer and lower-severity threats yield a higher score. A bonus is applied when your block rate exceeds 90%."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"Auth Security"})}),(0,b.jsx)("td",{children:"20%"}),(0,b.jsx)("td",{children:"Whether you have changed the default dashboard password and secret key, and whether Auth Shield is enabled. Using defaults penalizes this sub-score."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"Response Posture"})}),(0,b.jsx)("td",{children:"20%"}),(0,b.jsx)("td",{children:"The ratio of blocked threats to total threats. A 100% block rate yields a perfect sub-score. If the WAF is in log-only mode, unblocked threats lower this dimension."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"Header Compliance"})}),(0,b.jsx)("td",{children:"15%"}),(0,b.jsxs)("td",{children:["How many recommended security headers are configured: ",(0,b.jsx)("code",{children:"X-Frame-Options"}),","," ",(0,b.jsx)("code",{children:"Referrer-Policy"}),", ",(0,b.jsx)("code",{children:"Content-Security-Policy"}),", and"," ",(0,b.jsx)("code",{children:"Strict-Transport-Security"}),". ",(0,b.jsx)("code",{children:"X-Content-Type-Options"})," is always set by default."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"Rate Limiting"})}),(0,b.jsx)("td",{children:"15%"}),(0,b.jsx)("td",{children:"Whether rate limiting is enabled and how comprehensively it is configured: per-IP, per-user, and per-route limits each contribute to this sub-score."})]})]})]}),(0,b.jsx)("h2",{id:"how-it-works",children:"How It's Computed"}),(0,b.jsxs)("p",{children:["Sentinel launches a background goroutine when ",(0,b.jsx)("code",{children:"Mount"})," is called. The"," ",(0,b.jsx)("code",{children:"ScoreEngine"})," computes the score immediately on startup and then recomputes it every 5 minutes. Each cycle performs the following steps:"]}),(0,b.jsxs)("ol",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Query threat stats"})," — The engine calls ",(0,b.jsx)("code",{children:"GetThreatStats"})," on the storage layer with a 24-hour window to retrieve counts by severity and block status."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Evaluate each dimension"})," — Five dedicated functions compute a sub-score (0-100) for each dimension using the threat stats and the current ",(0,b.jsx)("code",{children:"Config"}),"."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Weighted aggregation"})," — Sub-scores are multiplied by their weights and summed to produce the overall score."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Grade assignment"})," — The overall score is mapped to a letter grade."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Recommendation generation"})," — The engine inspects each sub-score and the config to produce actionable recommendations for any weak areas."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Persist"})," — The result is saved to storage via"," ",(0,b.jsx)("code",{children:"SaveSecurityScore"})," so the dashboard and API can read it without recomputing."]})]}),(0,b.jsx)(c.default,{language:"go",filename:"intelligence/security_score.go",code:`// ComputeScore calculates the security score based on current state.
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
}`}),(0,b.jsx)("h3",{children:"Grading Scale"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Score Range"}),(0,b.jsx)("th",{children:"Grade"}),(0,b.jsx)("th",{children:"Interpretation"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"90 - 100"}),(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"A"})}),(0,b.jsx)("td",{children:"Excellent. All major features enabled and well-configured."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"80 - 89"}),(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"B"})}),(0,b.jsx)("td",{children:"Good. Minor improvements available."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"70 - 79"}),(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"C"})}),(0,b.jsx)("td",{children:"Fair. Some important features are missing or misconfigured."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"60 - 69"}),(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"D"})}),(0,b.jsx)("td",{children:"Poor. Significant gaps in your security posture."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"0 - 59"}),(0,b.jsx)("td",{children:(0,b.jsx)("strong",{children:"F"})}),(0,b.jsx)("td",{children:"Failing. Critical features are disabled or defaults are unchanged."})]})]})]}),(0,b.jsx)("h2",{id:"sub-score-details",children:"Sub-Score Details"}),(0,b.jsx)("h3",{children:"Threat Activity (30%)"}),(0,b.jsx)("p",{children:"Starts at 100 and deducts points for each threat detected in the last 24 hours. Deductions scale by severity: critical threats cost 20 points each, high costs 10, medium costs 5, and low costs 2. A bonus of +10 is applied when over 90% of threats are blocked, or +5 when over 50% are blocked. With no threats in the window, the sub-score is a perfect 100."}),(0,b.jsx)("h3",{children:"Auth Security (20%)"}),(0,b.jsxs)("p",{children:["Starts at a base of 50. Changing the default dashboard password from"," ",(0,b.jsx)("code",{children:'"sentinel"'})," adds 20 points. Changing the default secret key adds another 20. Enabling Auth Shield adds 10. A fully configured authentication setup scores 100."]}),(0,b.jsx)("h3",{children:"Response Posture (20%)"}),(0,b.jsx)("p",{children:"Measures the percentage of threats that were actively blocked. If all detected threats are blocked (WAF in block mode), the sub-score is 100. If no threats have been detected, the baseline score is 80. Running the WAF in log-only mode typically lowers this dimension because threats are recorded but not blocked."}),(0,b.jsx)("h3",{children:"Header Compliance (15%)"}),(0,b.jsxs)("p",{children:["Counts how many of the five recommended security headers are configured:"," ",(0,b.jsx)("code",{children:"X-Content-Type-Options"})," (always on), ",(0,b.jsx)("code",{children:"X-Frame-Options"}),","," ",(0,b.jsx)("code",{children:"Referrer-Policy"}),", ",(0,b.jsx)("code",{children:"Content-Security-Policy"}),", and"," ",(0,b.jsx)("code",{children:"Strict-Transport-Security"}),". Each configured header contributes equally. If security headers are explicitly disabled, the sub-score is 0."]}),(0,b.jsx)("h3",{children:"Rate Limiting (15%)"}),(0,b.jsx)("p",{children:"Awards a base of 30 points for having rate limiting enabled. Additional points come from configuring per-IP limits (+30), per-user limits (+20), and per-route limits (+20). Disabling rate limiting entirely results in a sub-score of 0."}),(0,b.jsx)(d.default,{type:"success",title:"Maximizing Your Score",children:"To reach an A grade: enable WAF in block mode, enable rate limiting with per-IP and per-user limits, configure all five security headers, change the default dashboard password and secret key, and enable Auth Shield. These settings cover all five dimensions."}),(0,b.jsx)("h2",{id:"recommendations",children:"Recommendations"}),(0,b.jsx)("p",{children:"After computing the score, the engine generates a list of actionable recommendations based on which features are disabled or which sub-scores fall below their thresholds. Each recommendation includes a title, description, impact level, and the category it addresses."}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Condition"}),(0,b.jsx)("th",{children:"Recommendation"}),(0,b.jsx)("th",{children:"Impact"}),(0,b.jsx)("th",{children:"Category"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"WAF disabled"}),(0,b.jsx)("td",{children:"Enable WAF to protect against common attacks"}),(0,b.jsx)("td",{children:"High"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"threat_activity"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"WAF in log-only mode"}),(0,b.jsx)("td",{children:"Set WAF to block mode to actively prevent attacks"}),(0,b.jsx)("td",{children:"High"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"response_posture"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Rate limiting disabled"}),(0,b.jsx)("td",{children:"Enable rate limiting to prevent abuse and brute force"}),(0,b.jsx)("td",{children:"Medium"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"rate_limit_coverage"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Header compliance below 80"}),(0,b.jsx)("td",{children:"Configure CSP and HSTS headers"}),(0,b.jsx)("td",{children:"Medium"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"header_compliance"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Auth security below 70"}),(0,b.jsx)("td",{children:"Change default passwords and enable Auth Shield"}),(0,b.jsx)("td",{children:"High"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"auth_security"})})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"intelligence/security_score.go",showLineNumbers:!1,code:`// Example recommendation structure
type Recommendation struct {
    Title       string \`json:"title"\`
    Description string \`json:"description"\`
    Impact      string \`json:"impact"\`       // "High", "Medium", "Low"
    Category    string \`json:"category"\`      // matches a sub-score dimension
}`}),(0,b.jsx)(d.default,{type:"warning",title:"Act on Recommendations",children:"Recommendations are not just informational. Each one directly maps to a sub-score dimension. Implementing a high-impact recommendation can raise your overall score by 10-20 points."}),(0,b.jsx)("h2",{id:"api",children:"API"}),(0,b.jsx)("p",{children:"The security score is available through a single authenticated endpoint. The response includes the overall score, grade, each sub-score with its weight and label, the computation timestamp, trend direction, and the list of recommendations."}),(0,b.jsx)("h3",{children:"Get Security Score"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Property"}),(0,b.jsx)("th",{children:"Value"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Endpoint"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"GET /sentinel/api/score"})})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Auth"}),(0,b.jsxs)("td",{children:["JWT token in ",(0,b.jsx)("code",{children:"Authorization: Bearer <token>"})]})]})]})]}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`curl -s -H "Authorization: Bearer <token>" \\
  "http://localhost:8080/sentinel/api/score" | jq .`}),(0,b.jsx)(c.default,{language:"json",filename:"Response",showLineNumbers:!1,code:`{
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
}`}),(0,b.jsx)("h2",{id:"dashboard",children:"Dashboard"}),(0,b.jsx)("p",{children:"The security score is surfaced in two places within the Sentinel dashboard:"}),(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Main Dashboard"})," — The home page displays the overall score as a ring gauge with the letter grade at the center. The gauge color shifts from red (F) through amber (C/D) to green (A/B), providing an instant visual indicator of your security posture."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Analytics Page"})," — The analytics section shows a detailed score breakdown with each sub-score displayed individually. This view lets you identify which specific dimension is dragging down your overall score and view the associated recommendations."]})]}),(0,b.jsxs)("p",{children:["Access the dashboard at ",(0,b.jsx)("code",{children:"http://localhost:8080/sentinel/ui"})," after mounting Sentinel."]}),(0,b.jsx)("h2",{id:"configuration",children:"Configuration"}),(0,b.jsxs)("p",{children:["The score engine does not have its own configuration block. It reads the main"," ",(0,b.jsx)("code",{children:"Config"})," you pass to ",(0,b.jsx)("code",{children:"sentinel.Mount"})," to determine which features are enabled and how they are configured. The sub-scores react directly to your config:"]}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Config Area"}),(0,b.jsx)("th",{children:"Affects Dimension"}),(0,b.jsx)("th",{children:"What the Engine Checks"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"WAF"})}),(0,b.jsx)("td",{children:"Threat Activity, Response Posture"}),(0,b.jsx)("td",{children:"Whether WAF is enabled and whether it is in block or log mode."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"RateLimit"})}),(0,b.jsx)("td",{children:"Rate Limiting"}),(0,b.jsx)("td",{children:"Whether rate limiting is enabled and which limit types are configured (by-IP, by-user, by-route)."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Headers"})}),(0,b.jsx)("td",{children:"Header Compliance"}),(0,b.jsx)("td",{children:"Which security headers are explicitly set in the config."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Dashboard"})}),(0,b.jsx)("td",{children:"Auth Security"}),(0,b.jsx)("td",{children:"Whether the password and secret key have been changed from their defaults."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"AuthShield"})}),(0,b.jsx)("td",{children:"Auth Security"}),(0,b.jsx)("td",{children:"Whether Auth Shield brute-force protection is enabled."})]})]})]}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`package main

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
}`}),(0,b.jsxs)(d.default,{type:"info",title:"Background Recomputation",children:["The score engine runs in a background goroutine that ticks every 5 minutes. It also computes the score once immediately on startup. The API endpoint"," ",(0,b.jsx)("code",{children:"GET /sentinel/api/score"})," triggers a fresh computation on each request, so you always get the latest result. The background goroutine ensures the persisted score stays current for the dashboard even when the API is not being called."]}),(0,b.jsx)("h2",{children:"Next Steps"}),(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/configuration",children:"Configuration Reference"})," — Full config field reference for all features that affect the score"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/waf",children:"WAF"})," — Enable and configure the WAF to improve Threat Activity and Response Posture"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/rate-limiting",children:"Rate Limiting"})," — Configure rate limits to boost the Rate Limiting dimension"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/security-headers",children:"Security Headers"})," — Add headers to maximize Header Compliance"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/auth-shield",children:"Auth Shield"})," — Enable brute-force protection to raise Auth Security"]})]})]})}a.s(["default",()=>e,"metadata",0,{title:"Security Score - Sentinel Docs"}])}];

//# sourceMappingURL=app_docs_security-score_page_jsx_23dbb554._.js.map