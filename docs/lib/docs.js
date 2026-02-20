export const sidebarNav = [
  {
    title: 'Getting Started',
    items: [
      { title: 'Introduction', href: '/docs/getting-started' },
      { title: 'Configuration', href: '/docs/configuration' },
    ],
  },
  {
    title: 'Security',
    items: [
      { title: 'WAF', href: '/docs/waf' },
      { title: 'Rate Limiting', href: '/docs/rate-limiting' },
      { title: 'Auth Shield', href: '/docs/auth-shield' },
      { title: 'Security Headers', href: '/docs/security-headers' },
    ],
  },
  {
    title: 'Intelligence',
    items: [
      { title: 'Threat Intelligence', href: '/docs/threat-intelligence' },
      { title: 'Anomaly Detection', href: '/docs/anomaly-detection' },
      { title: 'Security Score', href: '/docs/security-score' },
    ],
  },
  {
    title: 'Monitoring',
    items: [
      { title: 'Dashboard', href: '/docs/the-dashboard' },
      { title: 'Performance', href: '/docs/performance' },
      { title: 'Alerting', href: '/docs/alerting' },
    ],
  },
  {
    title: 'Data',
    items: [
      { title: 'Audit Logging', href: '/docs/audit-logging' },
      { title: 'AI Analysis', href: '/docs/ai-analysis' },
      { title: 'Compliance Reports', href: '/docs/compliance-reports' },
    ],
  },
  {
    title: 'Reference',
    items: [
      { title: 'API Reference', href: '/docs/api-reference' },
    ],
  },
];

export const searchIndex = [
  { title: 'Introduction', href: '/docs/getting-started', content: 'Getting started installation quick start mount gin router zero config sentinel SDK security middleware', section: 'Getting Started' },
  { title: 'Configuration', href: '/docs/configuration', content: 'Configuration options dashboard storage WAF rate limit auth shield headers anomaly alerts AI provider geolocation performance user extractor defaults', section: 'Getting Started' },
  { title: 'WAF', href: '/docs/waf', content: 'Web Application Firewall SQL injection XSS cross-site scripting path traversal command injection SSRF XXE custom rules regex patterns block log mode rule strictness severity', section: 'Security' },
  { title: 'Rate Limiting', href: '/docs/rate-limiting', content: 'Rate limiting per-IP per-user per-route global sliding window requests window duration 429 too many requests throttle', section: 'Security' },
  { title: 'Auth Shield', href: '/docs/auth-shield', content: 'Auth shield brute force protection login lockout failed attempts automatic block authentication', section: 'Security' },
  { title: 'Security Headers', href: '/docs/security-headers', content: 'Security headers CSP content security policy HSTS strict transport security X-Frame-Options X-Content-Type-Options referrer policy permissions policy', section: 'Security' },
  { title: 'Threat Intelligence', href: '/docs/threat-intelligence', content: 'Threat intelligence actor profiling risk scoring IP reputation geolocation geographic attribution threat events', section: 'Intelligence' },
  { title: 'Anomaly Detection', href: '/docs/anomaly-detection', content: 'Anomaly detection statistical analysis sensitivity levels unusual patterns baseline deviation traffic spikes', section: 'Intelligence' },
  { title: 'Security Score', href: '/docs/security-score', content: 'Security score weighted dimensions WAF coverage rate limiting anomalies threat response recommendations', section: 'Intelligence' },
  { title: 'Dashboard', href: '/docs/the-dashboard', content: 'Dashboard embedded React real-time WebSocket live updates dark theme threats actors IP management WAF analytics', section: 'Monitoring' },
  { title: 'Performance', href: '/docs/performance', content: 'Performance monitoring latency tracking p50 p95 p99 percentiles error rates response sizes throughput per-route metrics', section: 'Monitoring' },
  { title: 'Alerting', href: '/docs/alerting', content: 'Alerting notifications Slack email webhook severity thresholds dispatcher providers', section: 'Monitoring' },
  { title: 'Audit Logging', href: '/docs/audit-logging', content: 'Audit logging GORM plugin database changes create update delete tracking request context user attribution', section: 'Data' },
  { title: 'AI Analysis', href: '/docs/ai-analysis', content: 'AI analysis Claude OpenAI Gemini threat analysis actor assessment natural language query daily summary WAF recommendations provider', section: 'Data' },
  { title: 'Compliance Reports', href: '/docs/compliance-reports', content: 'Compliance reports GDPR PCI-DSS SOC2 data protection audit evidence regulatory', section: 'Data' },
  { title: 'API Reference', href: '/docs/api-reference', content: 'API reference REST endpoints authentication JWT threats actors IP lists WAF rules rate limits AI analytics reports WebSocket', section: 'Reference' },
];
