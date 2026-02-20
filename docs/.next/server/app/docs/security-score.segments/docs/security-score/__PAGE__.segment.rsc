1:"$Sreact.fragment"
2b:I[99151,["/_next/static/chunks/4cc5a908347f559b.js","/_next/static/chunks/c23263069b7f7ba3.js","/_next/static/chunks/2425b678dfc0c3cf.js"],"default"]
2f:I[35417,["/_next/static/chunks/26ca110782d86623.js","/_next/static/chunks/81f0f13d25d49d65.js"],"OutletBoundary"]
30:"$Sreact.suspense"
0:{"buildId":"5Swj18oapgqGqSZX8fol6","rsc":["$","$1","c",{"children":[[["$","h1",null,{"children":"Security Score"}],["$","p",null,{"children":["The Security Score is a weighted composite metric (0-100) that measures your application's overall security posture at a glance. It aggregates five dimensions of your Sentinel configuration and runtime behavior into a single number, graded from ",["$","strong",null,{"children":"A"}]," (90-100) to ",["$","strong",null,{"children":"F"}]," (below 60). The score updates automatically in the background and surfaces actionable recommendations to improve your defenses."]}],["$","div",null,{"className":"my-4 rounded-lg border p-4 bg-blue-50 dark:bg-blue-950/30 border-blue-200 dark:border-blue-800","children":["$","div",null,{"className":"flex items-start gap-3","children":[["$","svg",null,{"xmlns":"http://www.w3.org/2000/svg","width":18,"height":18,"viewBox":"0 0 24 24","fill":"none","stroke":"currentColor","strokeWidth":2,"strokeLinecap":"round","strokeLinejoin":"round","className":"lucide lucide-info mt-0.5 flex-shrink-0 text-blue-500","children":[["$","circle","1mglay",{"cx":"12","cy":"12","r":"10"}],["$","path","1dtifu",{"d":"M12 16v-4"}],["$","path","e9boi3",{"d":"M12 8h.01"}],"$undefined"]}],["$","div",null,{"children":[["$","p",null,{"className":"font-semibold text-sm mb-1 text-blue-800 dark:text-blue-300","children":"Always Active"}],["$","div",null,{"className":"text-sm text-gray-700 dark:text-gray-300","children":["The score engine runs automatically once Sentinel is mounted. There is no separate configuration to enable it. It uses the main ",["$","code",null,{"children":"Config"}]," you pass to"," ",["$","code",null,{"children":"sentinel.Mount"}]," to evaluate which features are active and how well they are configured."]}]]}]]}]}],["$","h2",null,{"id":"dimensions","children":"Score Dimensions"}],["$","p",null,{"children":"The overall score is a weighted sum of five sub-scores. Each dimension evaluates a different aspect of your security posture:"}],["$","table",null,{"children":[["$","thead",null,{"children":["$","tr",null,{"children":[["$","th",null,{"children":"Dimension"}],["$","th",null,{"children":"Weight"}],["$","th",null,{"children":"What It Measures"}]]}]}],["$","tbody",null,{"children":[["$","tr",null,{"children":[["$","td",null,{"children":["$","strong",null,{"children":"Threat Activity"}]}],["$","td",null,{"children":"30%"}],["$","td",null,{"children":"How many threats were detected in the last 24 hours and how severe they are. Fewer and lower-severity threats yield a higher score. A bonus is applied when your block rate exceeds 90%."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":["$","strong",null,{"children":"Auth Security"}]}],["$","td",null,{"children":"20%"}],["$","td",null,{"children":"Whether you have changed the default dashboard password and secret key, and whether Auth Shield is enabled. Using defaults penalizes this sub-score."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":["$","strong",null,{"children":"Response Posture"}]}],["$","td",null,{"children":"20%"}],["$","td",null,{"children":"The ratio of blocked threats to total threats. A 100% block rate yields a perfect sub-score. If the WAF is in log-only mode, unblocked threats lower this dimension."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":["$","strong",null,{"children":"Header Compliance"}]}],["$","td",null,{"children":"15%"}],["$","td",null,{"children":["How many recommended security headers are configured: ",["$","code",null,{"children":"X-Frame-Options"}],","," ",["$","code",null,{"children":"Referrer-Policy"}],", ",["$","code",null,{"children":"Content-Security-Policy"}],", and"," ",["$","code",null,{"children":"Strict-Transport-Security"}],". ",["$","code",null,{"children":"X-Content-Type-Options"}]," is always set by default."]}]]}],["$","tr",null,{"children":[["$","td",null,{"children":["$","strong",null,{"children":"Rate Limiting"}]}],["$","td",null,{"children":"15%"}],["$","td",null,{"children":"Whether rate limiting is enabled and how comprehensively it is configured: per-IP, per-user, and per-route limits each contribute to this sub-score."}]]}]]}]]}],["$","h2",null,{"id":"how-it-works","children":"How It's Computed"}],"$L2","$L3","$L4","$L5","$L6","$L7","$L8","$L9","$La","$Lb","$Lc","$Ld","$Le","$Lf","$L10","$L11","$L12","$L13","$L14","$L15","$L16","$L17","$L18","$L19","$L1a","$L1b","$L1c","$L1d","$L1e","$L1f","$L20","$L21","$L22","$L23","$L24","$L25","$L26","$L27","$L28"],["$L29"],"$L2a"]}],"loading":null,"isPartial":false}
2:["$","p",null,{"children":["Sentinel launches a background goroutine when ",["$","code",null,{"children":"Mount"}]," is called. The"," ",["$","code",null,{"children":"ScoreEngine"}]," computes the score immediately on startup and then recomputes it every 5 minutes. Each cycle performs the following steps:"]}]
3:["$","ol",null,{"children":[["$","li",null,{"children":[["$","strong",null,{"children":"Query threat stats"}]," — The engine calls ",["$","code",null,{"children":"GetThreatStats"}]," on the storage layer with a 24-hour window to retrieve counts by severity and block status."]}],["$","li",null,{"children":[["$","strong",null,{"children":"Evaluate each dimension"}]," — Five dedicated functions compute a sub-score (0-100) for each dimension using the threat stats and the current ",["$","code",null,{"children":"Config"}],"."]}],["$","li",null,{"children":[["$","strong",null,{"children":"Weighted aggregation"}]," — Sub-scores are multiplied by their weights and summed to produce the overall score."]}],["$","li",null,{"children":[["$","strong",null,{"children":"Grade assignment"}]," — The overall score is mapped to a letter grade."]}],["$","li",null,{"children":[["$","strong",null,{"children":"Recommendation generation"}]," — The engine inspects each sub-score and the config to produce actionable recommendations for any weak areas."]}],["$","li",null,{"children":[["$","strong",null,{"children":"Persist"}]," — The result is saved to storage via"," ",["$","code",null,{"children":"SaveSecurityScore"}]," so the dashboard and API can read it without recomputing."]}]]}]
2c:T4e5,// ComputeScore calculates the security score based on current state.
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
}4:["$","$L2b",null,{"language":"go","filename":"intelligence/security_score.go","code":"$2c"}]
5:["$","h3",null,{"children":"Grading Scale"}]
6:["$","table",null,{"children":[["$","thead",null,{"children":["$","tr",null,{"children":[["$","th",null,{"children":"Score Range"}],["$","th",null,{"children":"Grade"}],["$","th",null,{"children":"Interpretation"}]]}]}],["$","tbody",null,{"children":[["$","tr",null,{"children":[["$","td",null,{"children":"90 - 100"}],["$","td",null,{"children":["$","strong",null,{"children":"A"}]}],["$","td",null,{"children":"Excellent. All major features enabled and well-configured."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":"80 - 89"}],["$","td",null,{"children":["$","strong",null,{"children":"B"}]}],["$","td",null,{"children":"Good. Minor improvements available."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":"70 - 79"}],["$","td",null,{"children":["$","strong",null,{"children":"C"}]}],["$","td",null,{"children":"Fair. Some important features are missing or misconfigured."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":"60 - 69"}],["$","td",null,{"children":["$","strong",null,{"children":"D"}]}],["$","td",null,{"children":"Poor. Significant gaps in your security posture."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":"0 - 59"}],["$","td",null,{"children":["$","strong",null,{"children":"F"}]}],["$","td",null,{"children":"Failing. Critical features are disabled or defaults are unchanged."}]]}]]}]]}]
7:["$","h2",null,{"id":"sub-score-details","children":"Sub-Score Details"}]
8:["$","h3",null,{"children":"Threat Activity (30%)"}]
9:["$","p",null,{"children":"Starts at 100 and deducts points for each threat detected in the last 24 hours. Deductions scale by severity: critical threats cost 20 points each, high costs 10, medium costs 5, and low costs 2. A bonus of +10 is applied when over 90% of threats are blocked, or +5 when over 50% are blocked. With no threats in the window, the sub-score is a perfect 100."}]
a:["$","h3",null,{"children":"Auth Security (20%)"}]
b:["$","p",null,{"children":["Starts at a base of 50. Changing the default dashboard password from"," ",["$","code",null,{"children":"\"sentinel\""}]," adds 20 points. Changing the default secret key adds another 20. Enabling Auth Shield adds 10. A fully configured authentication setup scores 100."]}]
c:["$","h3",null,{"children":"Response Posture (20%)"}]
d:["$","p",null,{"children":"Measures the percentage of threats that were actively blocked. If all detected threats are blocked (WAF in block mode), the sub-score is 100. If no threats have been detected, the baseline score is 80. Running the WAF in log-only mode typically lowers this dimension because threats are recorded but not blocked."}]
e:["$","h3",null,{"children":"Header Compliance (15%)"}]
f:["$","p",null,{"children":["Counts how many of the five recommended security headers are configured:"," ",["$","code",null,{"children":"X-Content-Type-Options"}]," (always on), ",["$","code",null,{"children":"X-Frame-Options"}],","," ",["$","code",null,{"children":"Referrer-Policy"}],", ",["$","code",null,{"children":"Content-Security-Policy"}],", and"," ",["$","code",null,{"children":"Strict-Transport-Security"}],". Each configured header contributes equally. If security headers are explicitly disabled, the sub-score is 0."]}]
10:["$","h3",null,{"children":"Rate Limiting (15%)"}]
11:["$","p",null,{"children":"Awards a base of 30 points for having rate limiting enabled. Additional points come from configuring per-IP limits (+30), per-user limits (+20), and per-route limits (+20). Disabling rate limiting entirely results in a sub-score of 0."}]
12:["$","div",null,{"className":"my-4 rounded-lg border p-4 bg-green-50 dark:bg-green-950/30 border-green-200 dark:border-green-800","children":["$","div",null,{"className":"flex items-start gap-3","children":[["$","svg",null,{"xmlns":"http://www.w3.org/2000/svg","width":18,"height":18,"viewBox":"0 0 24 24","fill":"none","stroke":"currentColor","strokeWidth":2,"strokeLinecap":"round","strokeLinejoin":"round","className":"lucide lucide-circle-check-big mt-0.5 flex-shrink-0 text-green-500","children":[["$","path","yps3ct",{"d":"M21.801 10A10 10 0 1 1 17 3.335"}],["$","path","1pflzl",{"d":"m9 11 3 3L22 4"}],"$undefined"]}],["$","div",null,{"children":[["$","p",null,{"className":"font-semibold text-sm mb-1 text-green-800 dark:text-green-300","children":"Maximizing Your Score"}],["$","div",null,{"className":"text-sm text-gray-700 dark:text-gray-300","children":"To reach an A grade: enable WAF in block mode, enable rate limiting with per-IP and per-user limits, configure all five security headers, change the default dashboard password and secret key, and enable Auth Shield. These settings cover all five dimensions."}]]}]]}]}]
13:["$","h2",null,{"id":"recommendations","children":"Recommendations"}]
14:["$","p",null,{"children":"After computing the score, the engine generates a list of actionable recommendations based on which features are disabled or which sub-scores fall below their thresholds. Each recommendation includes a title, description, impact level, and the category it addresses."}]
15:["$","table",null,{"children":[["$","thead",null,{"children":["$","tr",null,{"children":[["$","th",null,{"children":"Condition"}],["$","th",null,{"children":"Recommendation"}],["$","th",null,{"children":"Impact"}],["$","th",null,{"children":"Category"}]]}]}],["$","tbody",null,{"children":[["$","tr",null,{"children":[["$","td",null,{"children":"WAF disabled"}],["$","td",null,{"children":"Enable WAF to protect against common attacks"}],["$","td",null,{"children":"High"}],["$","td",null,{"children":["$","code",null,{"children":"threat_activity"}]}]]}],["$","tr",null,{"children":[["$","td",null,{"children":"WAF in log-only mode"}],["$","td",null,{"children":"Set WAF to block mode to actively prevent attacks"}],["$","td",null,{"children":"High"}],["$","td",null,{"children":["$","code",null,{"children":"response_posture"}]}]]}],["$","tr",null,{"children":[["$","td",null,{"children":"Rate limiting disabled"}],["$","td",null,{"children":"Enable rate limiting to prevent abuse and brute force"}],["$","td",null,{"children":"Medium"}],["$","td",null,{"children":["$","code",null,{"children":"rate_limit_coverage"}]}]]}],["$","tr",null,{"children":[["$","td",null,{"children":"Header compliance below 80"}],["$","td",null,{"children":"Configure CSP and HSTS headers"}],["$","td",null,{"children":"Medium"}],["$","td",null,{"children":["$","code",null,{"children":"header_compliance"}]}]]}],["$","tr",null,{"children":[["$","td",null,{"children":"Auth security below 70"}],["$","td",null,{"children":"Change default passwords and enable Auth Shield"}],["$","td",null,{"children":"High"}],["$","td",null,{"children":["$","code",null,{"children":"auth_security"}]}]]}]]}]]}]
16:["$","$L2b",null,{"language":"go","filename":"intelligence/security_score.go","showLineNumbers":false,"code":"// Example recommendation structure\ntype Recommendation struct {\n    Title       string `json:\"title\"`\n    Description string `json:\"description\"`\n    Impact      string `json:\"impact\"`       // \"High\", \"Medium\", \"Low\"\n    Category    string `json:\"category\"`      // matches a sub-score dimension\n}"}]
17:["$","div",null,{"className":"my-4 rounded-lg border p-4 bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-800","children":["$","div",null,{"className":"flex items-start gap-3","children":[["$","svg",null,{"xmlns":"http://www.w3.org/2000/svg","width":18,"height":18,"viewBox":"0 0 24 24","fill":"none","stroke":"currentColor","strokeWidth":2,"strokeLinecap":"round","strokeLinejoin":"round","className":"lucide lucide-triangle-alert mt-0.5 flex-shrink-0 text-amber-500","children":[["$","path","wmoenq",{"d":"m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3"}],["$","path","juzpu7",{"d":"M12 9v4"}],["$","path","p32p05",{"d":"M12 17h.01"}],"$undefined"]}],["$","div",null,{"children":[["$","p",null,{"className":"font-semibold text-sm mb-1 text-amber-800 dark:text-amber-300","children":"Act on Recommendations"}],["$","div",null,{"className":"text-sm text-gray-700 dark:text-gray-300","children":"Recommendations are not just informational. Each one directly maps to a sub-score dimension. Implementing a high-impact recommendation can raise your overall score by 10-20 points."}]]}]]}]}]
18:["$","h2",null,{"id":"api","children":"API"}]
19:["$","p",null,{"children":"The security score is available through a single authenticated endpoint. The response includes the overall score, grade, each sub-score with its weight and label, the computation timestamp, trend direction, and the list of recommendations."}]
1a:["$","h3",null,{"children":"Get Security Score"}]
1b:["$","table",null,{"children":[["$","thead",null,{"children":["$","tr",null,{"children":[["$","th",null,{"children":"Property"}],["$","th",null,{"children":"Value"}]]}]}],["$","tbody",null,{"children":[["$","tr",null,{"children":[["$","td",null,{"children":"Endpoint"}],["$","td",null,{"children":["$","code",null,{"children":"GET /sentinel/api/score"}]}]]}],["$","tr",null,{"children":[["$","td",null,{"children":"Auth"}],["$","td",null,{"children":["JWT token in ",["$","code",null,{"children":"Authorization: Bearer <token>"}]]}]]}]]}]]}]
1c:["$","$L2b",null,{"language":"bash","showLineNumbers":false,"code":"curl -s -H \"Authorization: Bearer <token>\" \\\n  \"http://localhost:8080/sentinel/api/score\" | jq ."}]
2d:T466,{
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
}1d:["$","$L2b",null,{"language":"json","filename":"Response","showLineNumbers":false,"code":"$2d"}]
1e:["$","h2",null,{"id":"dashboard","children":"Dashboard"}]
1f:["$","p",null,{"children":"The security score is surfaced in two places within the Sentinel dashboard:"}]
20:["$","ul",null,{"children":[["$","li",null,{"children":[["$","strong",null,{"children":"Main Dashboard"}]," — The home page displays the overall score as a ring gauge with the letter grade at the center. The gauge color shifts from red (F) through amber (C/D) to green (A/B), providing an instant visual indicator of your security posture."]}],["$","li",null,{"children":[["$","strong",null,{"children":"Analytics Page"}]," — The analytics section shows a detailed score breakdown with each sub-score displayed individually. This view lets you identify which specific dimension is dragging down your overall score and view the associated recommendations."]}]]}]
21:["$","p",null,{"children":["Access the dashboard at ",["$","code",null,{"children":"http://localhost:8080/sentinel/ui"}]," after mounting Sentinel."]}]
22:["$","h2",null,{"id":"configuration","children":"Configuration"}]
23:["$","p",null,{"children":["The score engine does not have its own configuration block. It reads the main"," ",["$","code",null,{"children":"Config"}]," you pass to ",["$","code",null,{"children":"sentinel.Mount"}]," to determine which features are enabled and how they are configured. The sub-scores react directly to your config:"]}]
24:["$","table",null,{"children":[["$","thead",null,{"children":["$","tr",null,{"children":[["$","th",null,{"children":"Config Area"}],["$","th",null,{"children":"Affects Dimension"}],["$","th",null,{"children":"What the Engine Checks"}]]}]}],["$","tbody",null,{"children":[["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"WAF"}]}],["$","td",null,{"children":"Threat Activity, Response Posture"}],["$","td",null,{"children":"Whether WAF is enabled and whether it is in block or log mode."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"RateLimit"}]}],["$","td",null,{"children":"Rate Limiting"}],["$","td",null,{"children":"Whether rate limiting is enabled and which limit types are configured (by-IP, by-user, by-route)."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"Headers"}]}],["$","td",null,{"children":"Header Compliance"}],["$","td",null,{"children":"Which security headers are explicitly set in the config."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"Dashboard"}]}],["$","td",null,{"children":"Auth Security"}],["$","td",null,{"children":"Whether the password and secret key have been changed from their defaults."}]]}],["$","tr",null,{"children":[["$","td",null,{"children":["$","code",null,{"children":"AuthShield"}]}],["$","td",null,{"children":"Auth Security"}],["$","td",null,{"children":"Whether Auth Shield brute-force protection is enabled."}]]}]]}]]}]
2e:T6f9,package main

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
}25:["$","$L2b",null,{"language":"go","filename":"main.go","code":"$2e"}]
26:["$","div",null,{"className":"my-4 rounded-lg border p-4 bg-blue-50 dark:bg-blue-950/30 border-blue-200 dark:border-blue-800","children":["$","div",null,{"className":"flex items-start gap-3","children":[["$","svg",null,{"xmlns":"http://www.w3.org/2000/svg","width":18,"height":18,"viewBox":"0 0 24 24","fill":"none","stroke":"currentColor","strokeWidth":2,"strokeLinecap":"round","strokeLinejoin":"round","className":"lucide lucide-info mt-0.5 flex-shrink-0 text-blue-500","children":[["$","circle","1mglay",{"cx":"12","cy":"12","r":"10"}],["$","path","1dtifu",{"d":"M12 16v-4"}],["$","path","e9boi3",{"d":"M12 8h.01"}],"$undefined"]}],["$","div",null,{"children":[["$","p",null,{"className":"font-semibold text-sm mb-1 text-blue-800 dark:text-blue-300","children":"Background Recomputation"}],["$","div",null,{"className":"text-sm text-gray-700 dark:text-gray-300","children":["The score engine runs in a background goroutine that ticks every 5 minutes. It also computes the score once immediately on startup. The API endpoint"," ",["$","code",null,{"children":"GET /sentinel/api/score"}]," triggers a fresh computation on each request, so you always get the latest result. The background goroutine ensures the persisted score stays current for the dashboard even when the API is not being called."]}]]}]]}]}]
27:["$","h2",null,{"children":"Next Steps"}]
28:["$","ul",null,{"children":[["$","li",null,{"children":[["$","a",null,{"href":"/docs/configuration","children":"Configuration Reference"}]," — Full config field reference for all features that affect the score"]}],["$","li",null,{"children":[["$","a",null,{"href":"/docs/waf","children":"WAF"}]," — Enable and configure the WAF to improve Threat Activity and Response Posture"]}],["$","li",null,{"children":[["$","a",null,{"href":"/docs/rate-limiting","children":"Rate Limiting"}]," — Configure rate limits to boost the Rate Limiting dimension"]}],["$","li",null,{"children":[["$","a",null,{"href":"/docs/security-headers","children":"Security Headers"}]," — Add headers to maximize Header Compliance"]}],["$","li",null,{"children":[["$","a",null,{"href":"/docs/auth-shield","children":"Auth Shield"}]," — Enable brute-force protection to raise Auth Security"]}]]}]
29:["$","script","script-0",{"src":"/_next/static/chunks/2425b678dfc0c3cf.js","async":true}]
2a:["$","$L2f",null,{"children":["$","$30",null,{"name":"Next.MetadataOutlet","children":"$@31"}]}]
31:null
