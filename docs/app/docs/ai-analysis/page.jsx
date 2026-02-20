import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';

export const metadata = { title: 'AI Analysis - Sentinel Docs' };

export default function AIAnalysis() {
  return (
    <>
      <h1>AI Analysis</h1>
      <p>
        Sentinel includes an optional AI-powered analysis system that brings intelligent threat
        interpretation to your security data. By integrating with leading LLM providers —{' '}
        <strong>Anthropic Claude</strong>, <strong>OpenAI</strong>, or <strong>Google Gemini</strong>{' '}
        — Sentinel can generate plain-English explanations of threat events, assess the risk level of
        threat actors, summarize your daily security posture, answer natural language questions about
        your data, and even recommend new WAF rules based on recent attack patterns.
      </p>
      <p>
        AI analysis is entirely optional. When not configured, all AI endpoints gracefully return a
        message indicating that AI is not set up, and the dashboard shows setup instructions instead of
        analysis results. No API calls are made to any external service unless you explicitly provide a
        provider and API key.
      </p>

      <Callout type="info" title="Optional Feature">
        AI analysis requires a valid API key from one of the supported providers. Sentinel works
        perfectly without it — all core security features (WAF, rate limiting, anomaly detection,
        threat intelligence, alerting) operate independently of AI. Think of it as an intelligence
        layer on top of your existing security data.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  SUPPORTED PROVIDERS                                               */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="providers">Supported Providers</h2>
      <p>
        Sentinel supports three AI providers out of the box. Each provider uses a sensible default
        model, but you can override it with any model the provider supports.
      </p>

      <table>
        <thead>
          <tr>
            <th>Provider</th>
            <th>Constant</th>
            <th>Default Model</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>Claude</strong></td>
            <td><code>sentinel.Claude</code></td>
            <td><code>claude-sonnet-4-20250514</code></td>
            <td>Anthropic Claude. Excellent at nuanced security analysis and structured reasoning.</td>
          </tr>
          <tr>
            <td><strong>OpenAI</strong></td>
            <td><code>sentinel.OpenAI</code></td>
            <td><code>gpt-4o</code></td>
            <td>OpenAI GPT. Strong general-purpose analysis with broad security knowledge.</td>
          </tr>
          <tr>
            <td><strong>Gemini</strong></td>
            <td><code>sentinel.Gemini</code></td>
            <td><code>gemini-2.0-flash</code></td>
            <td>Google Gemini. Fast and cost-effective for high-volume analysis workloads.</td>
          </tr>
        </tbody>
      </table>

      {/* ------------------------------------------------------------------ */}
      {/*  CONFIGURATION                                                     */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="configuration">Configuration</h2>
      <p>
        AI analysis is configured through the <code>AI</code> field on the main{' '}
        <code>sentinel.Config</code> struct. This field is a pointer (<code>*AIConfig</code>),
        so setting it to <code>nil</code> (or simply omitting it) disables all AI features.
      </p>

      <h3>AIConfig</h3>
      <table>
        <thead>
          <tr>
            <th>Field</th>
            <th>Type</th>
            <th>Required</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>Provider</code></td>
            <td><code>AIProvider</code></td>
            <td>Yes</td>
            <td>Which AI provider to use: <code>sentinel.Claude</code>, <code>sentinel.OpenAI</code>, or <code>sentinel.Gemini</code>.</td>
          </tr>
          <tr>
            <td><code>APIKey</code></td>
            <td><code>string</code></td>
            <td>Yes</td>
            <td>Your API key for the chosen provider. Keep this secret — use environment variables in production.</td>
          </tr>
          <tr>
            <td><code>Model</code></td>
            <td><code>string</code></td>
            <td>No</td>
            <td>Optional model override. When empty, the default model for the chosen provider is used (see table above).</td>
          </tr>
          <tr>
            <td><code>DailySummary</code></td>
            <td><code>bool</code></td>
            <td>No</td>
            <td>When <code>true</code>, enables automatic daily summary generation.</td>
          </tr>
        </tbody>
      </table>

      <CodeBlock
        language="go"
        filename="core/config.go"
        code={`// AIConfig configures optional AI-powered analysis.
type AIConfig struct {
    Provider     AIProvider \`json:"provider"\`
    APIKey       string     \`json:"api_key"\`
    Model        string     \`json:"model,omitempty"\`
    DailySummary bool       \`json:"daily_summary,omitempty"\`
}

// AIProvider specifies which AI provider to use.
type AIProvider string

const (
    Claude AIProvider = "claude"
    OpenAI AIProvider = "openai"
    Gemini AIProvider = "gemini"
)`}
      />

      <h3>Basic Configuration (Claude)</h3>
      <CodeBlock
        language="go"
        filename="main.go"
        code={`sentinel.Mount(r, nil, sentinel.Config{
    WAF: sentinel.WAFConfig{
        Enabled: true,
        Mode:    sentinel.ModeBlock,
    },
    AI: &sentinel.AIConfig{
        Provider: sentinel.Claude,
        APIKey:   os.Getenv("ANTHROPIC_API_KEY"),
    },
})`}
      />

      <h3>OpenAI Configuration</h3>
      <CodeBlock
        language="go"
        filename="main.go"
        code={`AI: &sentinel.AIConfig{
    Provider: sentinel.OpenAI,
    APIKey:   os.Getenv("OPENAI_API_KEY"),
}`}
      />

      <h3>Gemini Configuration</h3>
      <CodeBlock
        language="go"
        filename="main.go"
        code={`AI: &sentinel.AIConfig{
    Provider: sentinel.Gemini,
    APIKey:   os.Getenv("GEMINI_API_KEY"),
}`}
      />

      <h3>Custom Model Override</h3>
      <p>
        If you want to use a specific model version instead of the default, set the{' '}
        <code>Model</code> field:
      </p>
      <CodeBlock
        language="go"
        code={`AI: &sentinel.AIConfig{
    Provider: sentinel.OpenAI,
    APIKey:   os.Getenv("OPENAI_API_KEY"),
    Model:    "gpt-4-turbo",  // Override the default gpt-4o
}`}
      />

      <Callout type="warning" title="Protect Your API Key">
        Never hardcode API keys in your source code. Use environment variables or a secrets manager.
        The examples above use <code>os.Getenv()</code> to load the key from the environment at
        runtime.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  CAPABILITIES                                                      */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="capabilities">AI Capabilities</h2>
      <p>
        Sentinel provides five distinct AI-powered analysis features. Each one is accessible via the
        dashboard UI and the REST API.
      </p>

      <h3 id="threat-analysis">1. Threat Analysis</h3>
      <p>
        Generate a detailed, plain-English analysis of a specific threat event. The AI examines the
        threat type, severity, payload, targeted route, and the associated actor profile to produce
        an explanation of what happened, why it matters, and what you should do about it.
      </p>
      <table>
        <thead>
          <tr>
            <th>Response Field</th>
            <th>Type</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>summary</code></td>
            <td><code>string</code></td>
            <td>A concise one-line summary of the threat.</td>
          </tr>
          <tr>
            <td><code>explanation</code></td>
            <td><code>string</code></td>
            <td>A detailed explanation of the attack technique and its implications.</td>
          </tr>
          <tr>
            <td><code>severity_assessment</code></td>
            <td><code>string</code></td>
            <td>The AI assessment of how severe this threat is in context.</td>
          </tr>
          <tr>
            <td><code>succeeded</code></td>
            <td><code>bool</code></td>
            <td>Whether the AI believes the attack succeeded.</td>
          </tr>
          <tr>
            <td><code>recommendations</code></td>
            <td><code>[]string</code></td>
            <td>Actionable recommendations for mitigating or preventing this threat.</td>
          </tr>
          <tr>
            <td><code>threat_category</code></td>
            <td><code>string</code></td>
            <td>The broad category the AI assigns to this threat.</td>
          </tr>
          <tr>
            <td><code>confidence</code></td>
            <td><code>int</code></td>
            <td>The AI confidence score (0-100) in its analysis.</td>
          </tr>
        </tbody>
      </table>

      <h3 id="actor-assessment">2. Actor Assessment</h3>
      <p>
        Generate a risk assessment of a threat actor based on their IP address, behavioral history,
        and recent events. The AI evaluates the actor&apos;s intent, sophistication level, and overall
        risk to your application.
      </p>
      <table>
        <thead>
          <tr>
            <th>Response Field</th>
            <th>Type</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>summary</code></td>
            <td><code>string</code></td>
            <td>A concise overview of the actor and their behavior.</td>
          </tr>
          <tr>
            <td><code>intent</code></td>
            <td><code>string</code></td>
            <td>The AI assessment of the actor&apos;s likely intent (e.g., reconnaissance, exploitation, data exfiltration).</td>
          </tr>
          <tr>
            <td><code>sophistication</code></td>
            <td><code>string</code></td>
            <td>The estimated skill level of the actor (e.g., script kiddie, intermediate, advanced).</td>
          </tr>
          <tr>
            <td><code>risk_level</code></td>
            <td><code>string</code></td>
            <td>Overall risk rating for this actor.</td>
          </tr>
          <tr>
            <td><code>recommendations</code></td>
            <td><code>[]string</code></td>
            <td>Suggested actions to take regarding this actor.</td>
          </tr>
          <tr>
            <td><code>related_groups</code></td>
            <td><code>[]string</code></td>
            <td>Known threat groups or campaigns the actor&apos;s behavior may be associated with.</td>
          </tr>
        </tbody>
      </table>

      <h3 id="daily-summary">3. Daily Summary</h3>
      <p>
        Generate an AI-powered summary of the last 24 hours of security events. This provides a
        high-level overview of your security posture, highlights the most significant threats,
        identifies trends, and offers strategic recommendations.
      </p>
      <table>
        <thead>
          <tr>
            <th>Response Field</th>
            <th>Type</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>summary</code></td>
            <td><code>string</code></td>
            <td>A narrative overview of the day&apos;s security events.</td>
          </tr>
          <tr>
            <td><code>highlights</code></td>
            <td><code>[]string</code></td>
            <td>Key events and milestones from the past 24 hours.</td>
          </tr>
          <tr>
            <td><code>top_threats</code></td>
            <td><code>[]string</code></td>
            <td>The most significant threats observed during the period.</td>
          </tr>
          <tr>
            <td><code>trend_analysis</code></td>
            <td><code>string</code></td>
            <td>Analysis of how threat patterns are evolving.</td>
          </tr>
          <tr>
            <td><code>recommendations</code></td>
            <td><code>[]string</code></td>
            <td>Strategic recommendations based on observed patterns.</td>
          </tr>
          <tr>
            <td><code>overall_status</code></td>
            <td><code>string</code></td>
            <td>A brief assessment of overall security health.</td>
          </tr>
        </tbody>
      </table>

      <h3 id="natural-language-query">4. Natural Language Query</h3>
      <p>
        Ask questions about your security data in plain English. The AI receives context about your
        recent threats, top actors, threat statistics, and security score, then answers your question
        using that live data.
      </p>

      <CodeBlock
        language="json"
        filename="Example Queries"
        showLineNumbers={false}
        code={`{ "query": "What are the most common attack types this week?" }
{ "query": "Is the IP 203.0.113.50 a serious threat?" }
{ "query": "Should I be worried about the spike in XSS attempts?" }
{ "query": "Summarize the threats targeting my /api/auth endpoint" }`}
      />

      <table>
        <thead>
          <tr>
            <th>Response Field</th>
            <th>Type</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>answer</code></td>
            <td><code>string</code></td>
            <td>The AI answer to your question, grounded in your actual security data.</td>
          </tr>
          <tr>
            <td><code>sources</code></td>
            <td><code>[]string</code></td>
            <td>References to the data sources used to answer the question.</td>
          </tr>
          <tr>
            <td><code>suggestions</code></td>
            <td><code>[]string</code></td>
            <td>Follow-up questions or actions the AI suggests.</td>
          </tr>
        </tbody>
      </table>

      <h3 id="waf-recommendations">5. WAF Recommendations</h3>
      <p>
        The AI analyzes recent threat events and suggests new WAF rules to improve your defenses.
        Each recommendation includes a rule ID, name, regex pattern, severity, the request components
        it should apply to, and the reasoning behind the suggestion.
      </p>
      <table>
        <thead>
          <tr>
            <th>Response Field</th>
            <th>Type</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>rule_id</code></td>
            <td><code>string</code></td>
            <td>A suggested unique ID for the rule.</td>
          </tr>
          <tr>
            <td><code>name</code></td>
            <td><code>string</code></td>
            <td>Human-readable name for the recommended rule.</td>
          </tr>
          <tr>
            <td><code>pattern</code></td>
            <td><code>string</code></td>
            <td>The regex pattern to match against requests.</td>
          </tr>
          <tr>
            <td><code>severity</code></td>
            <td><code>string</code></td>
            <td>Suggested severity level for matches.</td>
          </tr>
          <tr>
            <td><code>reason</code></td>
            <td><code>string</code></td>
            <td>Explanation of why this rule is recommended based on observed patterns.</td>
          </tr>
          <tr>
            <td><code>applies_to</code></td>
            <td><code>[]string</code></td>
            <td>Which request components to inspect (e.g., <code>path</code>, <code>query</code>, <code>headers</code>, <code>body</code>).</td>
          </tr>
        </tbody>
      </table>

      <Callout type="info" title="Review Before Applying">
        AI-generated WAF rules are suggestions, not automatic deployments. Always review the
        recommended patterns carefully and test them in <code>ModeLog</code> before enabling them
        in production. The AI may occasionally suggest overly broad patterns that could cause false
        positives.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  API ENDPOINTS                                                     */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="api-endpoints">API Endpoints</h2>
      <p>
        All AI endpoints are protected by dashboard authentication (JWT). They are available under
        the <code>/sentinel/api/ai</code> prefix by default.
      </p>

      <table>
        <thead>
          <tr>
            <th>Method</th>
            <th>Endpoint</th>
            <th>Description</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>POST</code></td>
            <td><code>/ai/analyze-threat/:id</code></td>
            <td>Analyze a specific threat event by its ID.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/ai/analyze-actor/:ip</code></td>
            <td>Generate a risk assessment for a threat actor by IP address.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/ai/daily-summary</code></td>
            <td>Generate an AI summary of the last 24 hours of security events.</td>
          </tr>
          <tr>
            <td><code>POST</code></td>
            <td><code>/ai/query</code></td>
            <td>Ask a natural language question about your security data.</td>
          </tr>
          <tr>
            <td><code>GET</code></td>
            <td><code>/ai/waf-recommendations</code></td>
            <td>Get AI-suggested WAF rules based on recent threats.</td>
          </tr>
        </tbody>
      </table>

      <h3>Analyze Threat</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Analyze a specific threat event
curl -X POST http://localhost:8080/sentinel/api/ai/analyze-threat/te-abc123 \\
  -H "Authorization: Bearer <token>"`}
      />

      <h3>Analyze Actor</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Get risk assessment for a threat actor
curl http://localhost:8080/sentinel/api/ai/analyze-actor/203.0.113.50 \\
  -H "Authorization: Bearer <token>"`}
      />

      <h3>Daily Summary</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Generate AI daily security summary
curl http://localhost:8080/sentinel/api/ai/daily-summary \\
  -H "Authorization: Bearer <token>"`}
      />

      <h3>Natural Language Query</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Ask a question about your security data
curl -X POST http://localhost:8080/sentinel/api/ai/query \\
  -H "Authorization: Bearer <token>" \\
  -H "Content-Type: application/json" \\
  -d '{"query": "What are the most targeted endpoints this week?"}'`}
      />

      <h3>WAF Recommendations</h3>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Get AI-suggested WAF rules
curl http://localhost:8080/sentinel/api/ai/waf-recommendations \\
  -H "Authorization: Bearer <token>"`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  CACHING                                                           */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="caching">Response Caching</h2>
      <p>
        To minimize API costs and improve response times, Sentinel wraps every AI provider with a{' '}
        <code>CachedProvider</code>. The caching layer intercepts requests and returns cached
        responses when available, falling back to the real provider only when the cache misses or
        expires.
      </p>

      <table>
        <thead>
          <tr>
            <th>Feature</th>
            <th>Cache Key</th>
            <th>Cached?</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td>Threat Analysis</td>
            <td><code>threat:&lt;threat_id&gt;</code></td>
            <td>Yes</td>
          </tr>
          <tr>
            <td>Actor Assessment</td>
            <td><code>actor:&lt;ip_address&gt;</code></td>
            <td>Yes</td>
          </tr>
          <tr>
            <td>Daily Summary</td>
            <td><code>daily:&lt;YYYY-MM-DD&gt;</code></td>
            <td>Yes</td>
          </tr>
          <tr>
            <td>Natural Language Query</td>
            <td>N/A</td>
            <td>No — each query is unique</td>
          </tr>
          <tr>
            <td>WAF Recommendations</td>
            <td><code>waf-rec:&lt;YYYY-MM-DD&gt;</code></td>
            <td>Yes</td>
          </tr>
        </tbody>
      </table>

      <p>
        The default cache TTL is <strong>1 hour</strong>. After the TTL expires, the next request for
        the same key triggers a fresh AI call. Natural language queries are never cached because each
        query is unique and users expect real-time answers.
      </p>

      <CodeBlock
        language="go"
        filename="ai/provider.go"
        code={`// CachedProvider wraps a Provider with response caching.
type CachedProvider struct {
    provider Provider
    cache    map[string]*cacheEntry
    mu       sync.RWMutex
    ttl      time.Duration
}

// NewCachedProvider creates a caching wrapper around any Provider.
func NewCachedProvider(provider Provider, ttl time.Duration) *CachedProvider {
    if ttl == 0 {
        ttl = 1 * time.Hour  // Default TTL
    }
    return &CachedProvider{
        provider: provider,
        cache:    make(map[string]*cacheEntry),
        ttl:      ttl,
    }
}`}
      />

      <Callout type="success" title="Cost Optimization">
        The caching layer significantly reduces API costs. Analyzing the same threat event multiple
        times (e.g., when multiple team members view the same event in the dashboard) only incurs
        one API call. Daily summaries and WAF recommendations are cached for the entire day, so
        repeated views are instant and free.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  GRACEFUL DEGRADATION                                              */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="graceful-degradation">Graceful Degradation</h2>
      <p>
        When AI is not configured (the <code>AI</code> field is <code>nil</code> or the API key is
        empty), Sentinel degrades gracefully rather than failing. All AI endpoints remain available
        but return a clear message indicating that AI is not set up.
      </p>

      <h3>API Response When AI Is Not Configured</h3>
      <CodeBlock
        language="json"
        filename="Response"
        showLineNumbers={false}
        code={`{
  "data": null,
  "message": "AI not configured"
}`}
      />

      <p>
        This consistent response format means your frontend or API consumers can check for the{' '}
        <code>message</code> field and display appropriate UI — such as a setup prompt or a
        feature explanation — without error handling.
      </p>

      <CodeBlock
        language="go"
        filename="ai/provider.go"
        code={`// NewProvider creates the appropriate Provider based on configuration.
// Returns nil if AI is not configured.
func NewProvider(config *AIConfig) Provider {
    if config == nil || config.APIKey == "" {
        return nil
    }
    // ... create provider based on config.Provider
}`}
      />

      <h3>Dashboard Behavior</h3>
      <p>
        When AI is not configured, the dashboard AI Insights page detects the{' '}
        <code>&quot;AI not configured&quot;</code> response and displays setup instructions instead
        of analysis results. This guides users through enabling the feature without showing error
        states.
      </p>

      <Callout type="info" title="No Breaking Changes">
        You can safely enable or disable AI at any time by adding or removing the{' '}
        <code>AI</code> config pointer. No other part of the system depends on AI being available.
        The WAF, rate limiter, anomaly detection, alerting, and all other features continue to
        operate normally regardless of AI configuration.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  DASHBOARD                                                         */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="dashboard">Dashboard — AI Insights</h2>
      <p>
        The Sentinel dashboard includes a dedicated <strong>AI Insights</strong> page that provides
        a visual interface for all five AI capabilities. Access it at{' '}
        <code>http://localhost:8080/sentinel/ui</code> and navigate to the AI Insights section.
      </p>

      <ul>
        <li>
          <strong>Threat Analysis</strong> — Click the &quot;Analyze with AI&quot; button on any
          threat event detail page to generate an in-depth analysis. The result includes the summary,
          explanation, severity assessment, confidence score, and actionable recommendations.
        </li>
        <li>
          <strong>Actor Assessment</strong> — From any threat actor profile page, trigger an AI risk
          assessment. The result shows the actor&apos;s likely intent, sophistication level, overall
          risk rating, and recommended actions.
        </li>
        <li>
          <strong>Daily Summary</strong> — The AI Insights page features a daily summary section that
          provides a narrative overview of the last 24 hours, including highlights, top threats, trend
          analysis, and strategic recommendations.
        </li>
        <li>
          <strong>Natural Language Query</strong> — A chat-like interface where you can type questions
          about your security data in plain English and receive AI-generated answers grounded in your
          live data.
        </li>
        <li>
          <strong>WAF Recommendations</strong> — A dedicated section that displays AI-suggested WAF
          rules with their patterns, severity levels, and the reasoning behind each recommendation.
          Review and apply them directly from the dashboard.
        </li>
      </ul>

      {/* ------------------------------------------------------------------ */}
      {/*  TESTING WITHOUT AN API KEY                                        */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="testing">Testing Without an API Key</h2>
      <p>
        You can run Sentinel with the AI feature unconfigured and everything works normally. The
        system gracefully handles the absence of an API key at every level:
      </p>

      <ol>
        <li>
          <strong>Provider creation</strong> — <code>ai.NewProvider(nil)</code> returns{' '}
          <code>nil</code> when the config is <code>nil</code> or the API key is empty. No provider
          is instantiated, no external connections are attempted.
        </li>
        <li>
          <strong>API handlers</strong> — Every AI handler checks if <code>aiProvider</code> is{' '}
          <code>nil</code> before proceeding. If it is, the handler returns an HTTP 200 with{' '}
          <code>{`{"data": null, "message": "AI not configured"}`}</code>.
        </li>
        <li>
          <strong>Dashboard</strong> — The frontend checks the API response and shows setup
          instructions rather than error messages when AI is not available.
        </li>
      </ol>

      <CodeBlock
        language="go"
        filename="main.go"
        code={`// AI is completely optional — just omit the AI field
sentinel.Mount(r, nil, sentinel.Config{
    WAF: sentinel.WAFConfig{
        Enabled: true,
        Mode:    sentinel.ModeBlock,
    },
    // AI: nil — not configured, all AI endpoints return gracefully
})`}
      />

      <Callout type="success" title="Safe to Explore">
        You can explore the AI Insights page in the dashboard even without an API key. The page
        loads normally and shows helpful information about what each feature does, along with
        configuration instructions. This makes it easy to evaluate the feature before committing
        to an API provider.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  FULL EXAMPLE                                                      */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="full-example">Full Configuration Example</h2>
      <p>
        The following example enables the WAF, alerting, and AI analysis with Claude. The AI
        system will analyze threats, assess actors, generate daily summaries, answer queries, and
        recommend WAF rules — all powered by Claude.
      </p>

      <CodeBlock
        language="go"
        filename="main.go"
        code={`package main

import (
    "os"

    sentinel "github.com/MUKE-coder/sentinel"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

    sentinel.Mount(r, nil, sentinel.Config{
        Dashboard: sentinel.DashboardConfig{
            Username:  "admin",
            Password:  "s3cur3-p4ss!",
            SecretKey: "my-jwt-secret-change-in-production",
        },

        WAF: sentinel.WAFConfig{
            Enabled: true,
            Mode:    sentinel.ModeBlock,
        },

        Alerts: sentinel.AlertConfig{
            MinSeverity: sentinel.SeverityHigh,
            Slack: &sentinel.SlackConfig{
                WebhookURL: os.Getenv("SLACK_WEBHOOK_URL"),
            },
        },

        // Enable AI analysis with Claude
        AI: &sentinel.AIConfig{
            Provider: sentinel.Claude,
            APIKey:   os.Getenv("ANTHROPIC_API_KEY"),
            // Model defaults to claude-sonnet-4-20250514
        },
    })

    r.GET("/api/data", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })

    r.Run(":8080")
}`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  NEXT STEPS                                                        */}
      {/* ------------------------------------------------------------------ */}

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/waf">WAF</a> — Configure the detection rules that generate threat events for AI analysis</li>
        <li><a href="/docs/threat-intelligence">Threat Intelligence</a> — Enrich threat actor profiles that feed into AI assessments</li>
        <li><a href="/docs/alerting">Alerting</a> — Get notified when high-severity threats are detected</li>
        <li><a href="/docs/anomaly-detection">Anomaly Detection</a> — Add behavioral analysis that complements AI insights</li>
        <li><a href="/docs/the-dashboard">Dashboard</a> — Explore the AI Insights page and other dashboard features</li>
      </ul>
    </>
  );
}
