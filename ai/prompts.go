package ai

import (
	"encoding/json"
	"fmt"
	"strings"

	sentinel "github.com/MUKE-coder/sentinel/core"
)

// buildThreatAnalysisPrompt creates the prompt for analyzing a specific threat event.
func buildThreatAnalysisPrompt(threat *sentinel.ThreatEvent, actor *sentinel.ThreatActor) string {
	var b strings.Builder
	b.WriteString("You are a cybersecurity expert analyzing a detected attack attempt against a web application.\n\n")

	b.WriteString("## Threat Event\n")
	b.WriteString(fmt.Sprintf("- **ID:** %s\n", threat.ID))
	b.WriteString(fmt.Sprintf("- **Timestamp:** %s\n", threat.Timestamp.Format("2006-01-02 15:04:05 UTC")))
	b.WriteString(fmt.Sprintf("- **Source IP:** %s\n", threat.IP))
	b.WriteString(fmt.Sprintf("- **Method:** %s\n", threat.Method))
	b.WriteString(fmt.Sprintf("- **Path:** %s\n", threat.Path))
	b.WriteString(fmt.Sprintf("- **Status Code:** %d\n", threat.StatusCode))
	b.WriteString(fmt.Sprintf("- **Threat Types:** %s\n", strings.Join(threat.ThreatTypes, ", ")))
	b.WriteString(fmt.Sprintf("- **Severity:** %s\n", threat.Severity))
	b.WriteString(fmt.Sprintf("- **Confidence:** %d%%\n", threat.Confidence))
	b.WriteString(fmt.Sprintf("- **Blocked:** %v\n", threat.Blocked))

	if threat.QueryParams != "" {
		b.WriteString(fmt.Sprintf("- **Query Params:** %s\n", threat.QueryParams))
	}
	if threat.BodySnippet != "" {
		b.WriteString(fmt.Sprintf("- **Body Snippet:** %s\n", threat.BodySnippet))
	}
	if threat.UserAgent != "" {
		b.WriteString(fmt.Sprintf("- **User-Agent:** %s\n", threat.UserAgent))
	}
	if threat.Country != "" {
		b.WriteString(fmt.Sprintf("- **Country:** %s\n", threat.Country))
	}

	if len(threat.Evidence) > 0 {
		b.WriteString("\n## Evidence\n")
		for _, e := range threat.Evidence {
			b.WriteString(fmt.Sprintf("- Pattern: `%s` matched `%s` in %s", e.Pattern, e.Matched, e.Location))
			if e.Parameter != "" {
				b.WriteString(fmt.Sprintf(" (param: %s)", e.Parameter))
			}
			b.WriteString("\n")
		}
	}

	if actor != nil {
		b.WriteString("\n## Attacker Profile\n")
		b.WriteString(fmt.Sprintf("- **Total Requests:** %d\n", actor.TotalRequests))
		b.WriteString(fmt.Sprintf("- **Threat Count:** %d\n", actor.ThreatCount))
		b.WriteString(fmt.Sprintf("- **Risk Score:** %d/100\n", actor.RiskScore))
		b.WriteString(fmt.Sprintf("- **Attack Types:** %s\n", strings.Join(actor.AttackTypes, ", ")))
		b.WriteString(fmt.Sprintf("- **First Seen:** %s\n", actor.FirstSeen.Format("2006-01-02 15:04:05")))
		b.WriteString(fmt.Sprintf("- **ISP:** %s\n", actor.ISP))
		if actor.AbuseScore > 0 {
			b.WriteString(fmt.Sprintf("- **AbuseIPDB Score:** %d/100\n", actor.AbuseScore))
		}
	}

	b.WriteString("\n## Instructions\n")
	b.WriteString("Analyze this attack attempt and provide your response as a JSON object with these fields:\n")
	b.WriteString("- `summary`: A 1-2 sentence plain-English summary of what the attacker was trying to do\n")
	b.WriteString("- `explanation`: A detailed explanation of the attack technique, what it targets, and potential impact\n")
	b.WriteString("- `severity_assessment`: Your own assessment of severity (Critical/High/Medium/Low) with reasoning\n")
	b.WriteString("- `succeeded`: Whether the attack likely succeeded based on the status code and blocking status\n")
	b.WriteString("- `recommendations`: Array of 2-4 specific recommended actions\n")
	b.WriteString("- `threat_category`: The OWASP or standard threat category this falls under\n")
	b.WriteString("- `confidence`: Your confidence in this analysis (0-100)\n")
	b.WriteString("\nRespond ONLY with valid JSON, no markdown formatting or code blocks.\n")

	return b.String()
}

// buildActorAnalysisPrompt creates the prompt for analyzing a threat actor.
func buildActorAnalysisPrompt(actor *sentinel.ThreatActor, recentEvents []*sentinel.ThreatEvent) string {
	var b strings.Builder
	b.WriteString("You are a cybersecurity threat intelligence analyst. Assess this threat actor based on their observed behavior.\n\n")

	b.WriteString("## Actor Profile\n")
	b.WriteString(fmt.Sprintf("- **IP:** %s\n", actor.IP))
	b.WriteString(fmt.Sprintf("- **Country:** %s\n", actor.Country))
	if actor.City != "" {
		b.WriteString(fmt.Sprintf("- **City:** %s\n", actor.City))
	}
	b.WriteString(fmt.Sprintf("- **ISP:** %s\n", actor.ISP))
	b.WriteString(fmt.Sprintf("- **First Seen:** %s\n", actor.FirstSeen.Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("- **Last Seen:** %s\n", actor.LastSeen.Format("2006-01-02 15:04:05")))
	b.WriteString(fmt.Sprintf("- **Total Requests:** %d\n", actor.TotalRequests))
	b.WriteString(fmt.Sprintf("- **Threat Count:** %d\n", actor.ThreatCount))
	b.WriteString(fmt.Sprintf("- **Risk Score:** %d/100\n", actor.RiskScore))
	b.WriteString(fmt.Sprintf("- **Attack Types:** %s\n", strings.Join(actor.AttackTypes, ", ")))
	b.WriteString(fmt.Sprintf("- **Targeted Routes:** %s\n", strings.Join(actor.TargetedRoutes, ", ")))
	b.WriteString(fmt.Sprintf("- **Status:** %s\n", actor.Status))
	if actor.AbuseScore > 0 {
		b.WriteString(fmt.Sprintf("- **AbuseIPDB Score:** %d/100\n", actor.AbuseScore))
	}
	b.WriteString(fmt.Sprintf("- **Known Bad Actor:** %v\n", actor.IsKnownBadActor))

	if len(recentEvents) > 0 {
		b.WriteString("\n## Recent Attack Events (last 10)\n")
		limit := len(recentEvents)
		if limit > 10 {
			limit = 10
		}
		for _, e := range recentEvents[:limit] {
			b.WriteString(fmt.Sprintf("- [%s] %s %s — %s (severity: %s, blocked: %v)\n",
				e.Timestamp.Format("15:04:05"),
				e.Method, e.Path,
				strings.Join(e.ThreatTypes, "/"),
				e.Severity, e.Blocked))
		}
	}

	b.WriteString("\n## Instructions\n")
	b.WriteString("Assess this threat actor and provide your response as a JSON object with these fields:\n")
	b.WriteString("- `summary`: 2-3 sentence assessment of who this actor is and what they're doing\n")
	b.WriteString("- `intent`: The likely intent (reconnaissance, exploitation, data_exfiltration, credential_stuffing, vulnerability_scanning, automated_attack, targeted_attack)\n")
	b.WriteString("- `sophistication`: Level of sophistication (script_kiddie, intermediate, advanced, apt)\n")
	b.WriteString("- `risk_level`: Overall risk level (critical, high, medium, low)\n")
	b.WriteString("- `recommendations`: Array of 2-4 specific recommended actions for this actor\n")
	b.WriteString("- `related_groups`: Array of known threat groups this behavior pattern resembles (empty if none)\n")
	b.WriteString("\nRespond ONLY with valid JSON, no markdown formatting or code blocks.\n")

	return b.String()
}

// buildDailySummaryPrompt creates the prompt for generating a daily security summary.
func buildDailySummaryPrompt(stats *sentinel.ThreatStats) string {
	var b strings.Builder
	b.WriteString("You are a cybersecurity analyst writing a daily security briefing for a security operations team.\n\n")

	b.WriteString("## Today's Threat Statistics\n")
	b.WriteString(fmt.Sprintf("- **Total Threats Detected:** %d\n", stats.TotalThreats))
	b.WriteString(fmt.Sprintf("- **Critical:** %d\n", stats.CriticalCount))
	b.WriteString(fmt.Sprintf("- **High:** %d\n", stats.HighCount))
	b.WriteString(fmt.Sprintf("- **Medium:** %d\n", stats.MediumCount))
	b.WriteString(fmt.Sprintf("- **Low:** %d\n", stats.LowCount))
	b.WriteString(fmt.Sprintf("- **Blocked:** %d\n", stats.BlockedCount))
	b.WriteString(fmt.Sprintf("- **Unique Attacker IPs:** %d\n", stats.UniqueIPs))

	if len(stats.TopAttackTypes) > 0 {
		b.WriteString("\n## Top Attack Types\n")
		for _, at := range stats.TopAttackTypes {
			b.WriteString(fmt.Sprintf("- %s: %d events\n", at.Type, at.Count))
		}
	}

	b.WriteString("\n## Instructions\n")
	b.WriteString("Write a daily security briefing and provide your response as a JSON object with these fields:\n")
	b.WriteString("- `summary`: A 3-5 sentence executive summary of today's security situation in plain English\n")
	b.WriteString("- `highlights`: Array of 3-5 key findings or notable events\n")
	b.WriteString("- `top_threats`: Array of the most concerning threats described in plain English\n")
	b.WriteString("- `trend_analysis`: Analysis of attack patterns and any trends observed\n")
	b.WriteString("- `recommendations`: Array of 2-4 priority actions for the security team\n")
	b.WriteString("- `overall_status`: One of: secure, elevated, concerning, critical\n")
	b.WriteString("\nRespond ONLY with valid JSON, no markdown formatting or code blocks.\n")

	return b.String()
}

// buildNLQueryPrompt creates the prompt for a natural language security query.
func buildNLQueryPrompt(query string, secCtx *SecurityContext) string {
	var b strings.Builder
	b.WriteString("You are a security assistant for a web application firewall (WAF) system. Answer the user's question using the provided security data.\n\n")

	b.WriteString("## Available Security Data\n\n")

	if secCtx.ThreatStats != nil {
		b.WriteString("### Threat Statistics\n")
		b.WriteString(fmt.Sprintf("- Total threats: %d (Critical: %d, High: %d, Medium: %d, Low: %d)\n",
			secCtx.ThreatStats.TotalThreats,
			secCtx.ThreatStats.CriticalCount,
			secCtx.ThreatStats.HighCount,
			secCtx.ThreatStats.MediumCount,
			secCtx.ThreatStats.LowCount))
		b.WriteString(fmt.Sprintf("- Blocked: %d, Unique IPs: %d\n", secCtx.ThreatStats.BlockedCount, secCtx.ThreatStats.UniqueIPs))
		if len(secCtx.ThreatStats.TopAttackTypes) > 0 {
			types := make([]string, 0, len(secCtx.ThreatStats.TopAttackTypes))
			for _, t := range secCtx.ThreatStats.TopAttackTypes {
				types = append(types, fmt.Sprintf("%s(%d)", t.Type, t.Count))
			}
			b.WriteString(fmt.Sprintf("- Attack types: %s\n", strings.Join(types, ", ")))
		}
	}

	if secCtx.Score != nil {
		b.WriteString(fmt.Sprintf("\n### Security Score: %d/100 (Grade: %s)\n", secCtx.Score.Overall, secCtx.Score.Grade))
	}

	if len(secCtx.RecentThreats) > 0 {
		b.WriteString("\n### Recent Threats\n")
		limit := len(secCtx.RecentThreats)
		if limit > 20 {
			limit = 20
		}
		for _, t := range secCtx.RecentThreats[:limit] {
			b.WriteString(fmt.Sprintf("- [%s] %s from %s (%s) — %s %s, severity: %s, blocked: %v",
				t.Timestamp.Format("2006-01-02 15:04"),
				strings.Join(t.ThreatTypes, "/"),
				t.IP, t.Country,
				t.Method, t.Path,
				t.Severity, t.Blocked))
			if t.QueryParams != "" {
				b.WriteString(fmt.Sprintf(", query: %s", t.QueryParams))
			}
			b.WriteString("\n")
		}
	}

	if len(secCtx.TopActors) > 0 {
		b.WriteString("\n### Top Threat Actors\n")
		limit := len(secCtx.TopActors)
		if limit > 10 {
			limit = 10
		}
		for _, a := range secCtx.TopActors[:limit] {
			b.WriteString(fmt.Sprintf("- %s (%s, %s) — %d threats, risk: %d/100, types: %s\n",
				a.IP, a.Country, a.ISP, a.ThreatCount, a.RiskScore, strings.Join(a.AttackTypes, "/")))
		}
	}

	b.WriteString(fmt.Sprintf("\n## User Question\n%s\n", query))

	b.WriteString("\n## Instructions\n")
	b.WriteString("Answer the question using the provided data. Provide your response as a JSON object with these fields:\n")
	b.WriteString("- `answer`: Clear, detailed answer to the question in plain English\n")
	b.WriteString("- `sources`: Array of data sources used (e.g., 'threat_stats', 'recent_threats', 'actors')\n")
	b.WriteString("- `suggestions`: Array of 1-3 follow-up questions the user might want to ask\n")
	b.WriteString("\nRespond ONLY with valid JSON, no markdown formatting or code blocks.\n")

	return b.String()
}

// buildWAFRecommendationsPrompt creates the prompt for WAF rule recommendations.
func buildWAFRecommendationsPrompt(recentThreats []*sentinel.ThreatEvent) string {
	var b strings.Builder
	b.WriteString("You are a WAF security engineer. Based on recent attack patterns, recommend custom WAF rules to improve protection.\n\n")

	b.WriteString("## Recent Attack Patterns\n")

	// Group threats by type for a cleaner summary
	typeCount := make(map[string]int)
	typePaths := make(map[string][]string)
	typePayloads := make(map[string][]string)
	for _, t := range recentThreats {
		for _, tt := range t.ThreatTypes {
			typeCount[tt]++
			if len(typePaths[tt]) < 5 {
				typePaths[tt] = append(typePaths[tt], t.Method+" "+t.Path)
			}
			if t.QueryParams != "" && len(typePayloads[tt]) < 3 {
				typePayloads[tt] = append(typePayloads[tt], t.QueryParams)
			}
			if t.BodySnippet != "" && len(typePayloads[tt]) < 3 {
				typePayloads[tt] = append(typePayloads[tt], t.BodySnippet)
			}
		}
	}

	for threatType, count := range typeCount {
		b.WriteString(fmt.Sprintf("\n### %s (%d events)\n", threatType, count))
		b.WriteString("Targeted endpoints:\n")
		for _, p := range typePaths[threatType] {
			b.WriteString(fmt.Sprintf("  - %s\n", p))
		}
		if payloads, ok := typePayloads[threatType]; ok && len(payloads) > 0 {
			b.WriteString("Sample payloads:\n")
			for _, p := range payloads {
				b.WriteString(fmt.Sprintf("  - `%s`\n", p))
			}
		}
	}

	b.WriteString("\n## Instructions\n")
	b.WriteString("Recommend 2-5 custom WAF rules to block these attack patterns. Each rule should use a Go-compatible regular expression.\n")
	b.WriteString("Provide your response as a JSON array of objects, each with these fields:\n")
	b.WriteString("- `rule_id`: A short kebab-case identifier (e.g., 'block-admin-scanner')\n")
	b.WriteString("- `name`: Human-readable rule name\n")
	b.WriteString("- `pattern`: Go-compatible regex pattern that detects the attack\n")
	b.WriteString("- `severity`: One of: Critical, High, Medium, Low\n")
	b.WriteString("- `reason`: Why this rule is recommended based on the observed patterns\n")
	b.WriteString("- `applies_to`: Array of where to check: path, query, body, header\n")
	b.WriteString("\nRespond ONLY with valid JSON, no markdown formatting or code blocks.\n")

	return b.String()
}

// marshalForPrompt serializes a value to compact JSON for embedding in prompts.
func marshalForPrompt(v interface{}) string {
	data, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(data)
}
