import Link from 'next/link';
import {
  Shield, Zap, Activity, Brain, FileText, Bell,
  Lock, Eye, BarChart3, Terminal, ArrowRight, ChevronRight,
  Globe, Gauge, Database, GitBranch
} from 'lucide-react';

const features = [
  {
    icon: Shield,
    title: 'Web Application Firewall',
    description: 'SQL injection, XSS, path traversal, command injection detection with configurable strictness and custom regex rules.',
    href: '/docs/waf',
  },
  {
    icon: Zap,
    title: 'Rate Limiting',
    description: 'Multi-dimensional rate limiting per IP, user, route, and globally with sliding window counters.',
    href: '/docs/rate-limiting',
  },
  {
    icon: Eye,
    title: 'Threat Intelligence',
    description: 'Automatic threat actor profiling, risk scoring, IP reputation checking, and geographic attribution.',
    href: '/docs/threat-intelligence',
  },
  {
    icon: Activity,
    title: 'Anomaly Detection',
    description: 'Statistical anomaly detection with configurable sensitivity for identifying unusual traffic patterns.',
    href: '/docs/anomaly-detection',
  },
  {
    icon: Lock,
    title: 'Auth Shield',
    description: 'Brute-force protection with automatic account lockouts after configurable failed attempts.',
    href: '/docs/auth-shield',
  },
  {
    icon: Database,
    title: 'Audit Logging',
    description: 'GORM plugin for automatic database change tracking with user attribution and request context.',
    href: '/docs/audit-logging',
  },
  {
    icon: Brain,
    title: 'AI Analysis',
    description: 'Optional Claude, OpenAI, or Gemini integration for intelligent threat analysis and natural language queries.',
    href: '/docs/ai-analysis',
  },
  {
    icon: FileText,
    title: 'Compliance Reports',
    description: 'Generate GDPR, PCI-DSS, and SOC 2 compliance reports with exportable JSON data.',
    href: '/docs/compliance-reports',
  },
  {
    icon: Bell,
    title: 'Alerting',
    description: 'Real-time notifications via Slack, email, and webhooks with configurable severity thresholds.',
    href: '/docs/alerting',
  },
  {
    icon: BarChart3,
    title: 'Dashboard',
    description: 'Embedded React dashboard with 13 pages, live WebSocket updates, charts, and management tools.',
    href: '/docs/the-dashboard',
  },
  {
    icon: Gauge,
    title: 'Performance Monitoring',
    description: 'Per-route latency tracking (p50/p95/p99), error rates, and response size metrics.',
    href: '/docs/performance',
  },
  {
    icon: Globe,
    title: 'Security Headers',
    description: 'Automatic HTTP security headers including CSP, HSTS, X-Frame-Options, and more.',
    href: '/docs/security-headers',
  },
];

const stats = [
  { label: 'Test Suites', value: '12' },
  { label: 'Benchmarks', value: '15' },
  { label: 'Dashboard Pages', value: '13' },
  { label: 'API Endpoints', value: '40+' },
];

export default function Home() {
  return (
    <div className="relative">
      {/* Hero */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-b from-sentinel-50/50 via-transparent to-transparent dark:from-sentinel-950/30 dark:via-transparent" />
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-[800px] h-[600px] bg-sentinel-400/10 dark:bg-sentinel-400/5 rounded-full blur-3xl" />

        <div className="relative max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 pt-20 pb-24 sm:pt-32 sm:pb-32">
          <div className="text-center max-w-3xl mx-auto">
            <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-sentinel-100 dark:bg-sentinel-900/50 text-sentinel-700 dark:text-sentinel-300 text-sm font-medium mb-8">
              <Shield size={14} />
              Production-grade security for Go
            </div>

            <h1 className="text-5xl sm:text-6xl lg:text-7xl font-extrabold tracking-tight mb-6">
              <span className="bg-gradient-to-r from-gray-900 via-gray-800 to-gray-700 dark:from-white dark:via-gray-200 dark:to-gray-400 bg-clip-text text-transparent">
                Security Intelligence
              </span>
              <br />
              <span className="bg-gradient-to-r from-sentinel-500 to-sentinel-700 dark:from-sentinel-300 dark:to-sentinel-500 bg-clip-text text-transparent">
                SDK for Go
              </span>
            </h1>

            <p className="text-lg sm:text-xl text-gray-600 dark:text-gray-400 mb-10 max-w-2xl mx-auto leading-relaxed">
              Drop-in WAF, rate limiting, threat detection, AI analysis, and a real-time dashboard for your Gin application. Mount with a single function call.
            </p>

            <div className="flex flex-col sm:flex-row items-center justify-center gap-4">
              <Link
                href="/docs/getting-started"
                className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-sentinel-500 hover:bg-sentinel-600 text-white font-medium text-sm transition-colors shadow-lg shadow-sentinel-500/25"
              >
                Get Started
                <ArrowRight size={16} />
              </Link>
              <Link
                href="https://github.com/MUKE-coder/sentinel"
                className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-gray-100 dark:bg-gray-800 hover:bg-gray-200 dark:hover:bg-gray-700 text-gray-900 dark:text-gray-100 font-medium text-sm transition-colors"
              >
                <GitBranch size={16} />
                View on GitHub
              </Link>
            </div>
          </div>

          {/* Code preview */}
          <div className="mt-16 max-w-2xl mx-auto">
            <div className="rounded-xl overflow-hidden border border-gray-200 dark:border-gray-800 shadow-2xl">
              <div className="flex items-center gap-2 px-4 py-3 bg-gray-50 dark:bg-gray-900 border-b border-gray-200 dark:border-gray-800">
                <div className="flex gap-1.5">
                  <div className="w-3 h-3 rounded-full bg-red-400" />
                  <div className="w-3 h-3 rounded-full bg-yellow-400" />
                  <div className="w-3 h-3 rounded-full bg-green-400" />
                </div>
                <span className="text-xs text-gray-500 font-mono ml-2">main.go</span>
              </div>
              <div className="bg-white dark:bg-[#011627] p-5 font-mono text-sm leading-relaxed">
                <div><span className="text-purple-600 dark:text-purple-400">r</span> <span className="text-gray-500">:=</span> <span className="text-blue-600 dark:text-blue-400">gin</span><span className="text-gray-500">.</span><span className="text-yellow-600 dark:text-yellow-400">Default</span><span className="text-gray-500">()</span></div>
                <div className="mt-1"><span className="text-blue-600 dark:text-blue-400">sentinel</span><span className="text-gray-500">.</span><span className="text-yellow-600 dark:text-yellow-400">Mount</span><span className="text-gray-500">(</span><span className="text-purple-600 dark:text-purple-400">r</span><span className="text-gray-500">,</span> <span className="text-orange-600 dark:text-orange-400">nil</span><span className="text-gray-500">,</span> <span className="text-blue-600 dark:text-blue-400">sentinel</span><span className="text-gray-500">.</span><span className="text-green-600 dark:text-green-400">Config</span><span className="text-gray-500">{'{'}{'}'}</span><span className="text-gray-500">)</span></div>
                <div className="mt-1"><span className="text-purple-600 dark:text-purple-400">r</span><span className="text-gray-500">.</span><span className="text-yellow-600 dark:text-yellow-400">Run</span><span className="text-gray-500">(</span><span className="text-green-600 dark:text-green-400">&quot;:8080&quot;</span><span className="text-gray-500">)</span></div>
                <div className="mt-3 text-gray-400 dark:text-gray-600">// Dashboard at http://localhost:8080/sentinel/ui</div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Stats */}
      <section className="border-y border-gray-200 dark:border-gray-800 bg-gray-50/50 dark:bg-gray-900/50">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-12">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-8">
            {stats.map((stat) => (
              <div key={stat.label} className="text-center">
                <div className="text-3xl font-bold text-gray-900 dark:text-white">{stat.value}</div>
                <div className="text-sm text-gray-500 dark:text-gray-400 mt-1">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Features */}
      <section className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24">
        <div className="text-center mb-16">
          <h2 className="text-3xl sm:text-4xl font-bold tracking-tight mb-4">
            Everything you need to secure your app
          </h2>
          <p className="text-lg text-gray-600 dark:text-gray-400 max-w-2xl mx-auto">
            Sentinel provides a comprehensive security layer with zero mandatory configuration. Enable what you need, when you need it.
          </p>
        </div>

        <div className="grid sm:grid-cols-2 lg:grid-cols-3 gap-6">
          {features.map((feature) => {
            const Icon = feature.icon;
            return (
              <Link
                key={feature.title}
                href={feature.href}
                className="group relative p-6 rounded-xl border border-gray-200 dark:border-gray-800 hover:border-sentinel-300 dark:hover:border-sentinel-700 bg-white dark:bg-gray-900 hover:shadow-lg transition-all"
              >
                <div className="w-10 h-10 rounded-lg bg-sentinel-50 dark:bg-sentinel-950/50 flex items-center justify-center mb-4">
                  <Icon size={20} className="text-sentinel-500" />
                </div>
                <h3 className="text-lg font-semibold mb-2 group-hover:text-sentinel-500 transition-colors">
                  {feature.title}
                </h3>
                <p className="text-sm text-gray-600 dark:text-gray-400 leading-relaxed">
                  {feature.description}
                </p>
                <ChevronRight
                  size={16}
                  className="absolute top-6 right-6 text-gray-300 dark:text-gray-700 group-hover:text-sentinel-500 transition-colors"
                />
              </Link>
            );
          })}
        </div>
      </section>

      {/* CTA */}
      <section className="border-t border-gray-200 dark:border-gray-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-24 text-center">
          <h2 className="text-3xl font-bold tracking-tight mb-4">Ready to secure your Go application?</h2>
          <p className="text-lg text-gray-600 dark:text-gray-400 mb-8 max-w-xl mx-auto">
            Install Sentinel and add enterprise-grade security to your Gin app in under 5 minutes.
          </p>
          <div className="inline-flex items-center gap-3 px-6 py-3 rounded-xl bg-gray-100 dark:bg-gray-800 font-mono text-sm mb-8">
            <Terminal size={16} className="text-gray-400" />
            <span>go get github.com/MUKE-coder/sentinel</span>
          </div>
          <div className="flex items-center justify-center gap-4">
            <Link
              href="/docs/getting-started"
              className="inline-flex items-center gap-2 px-6 py-3 rounded-xl bg-sentinel-500 hover:bg-sentinel-600 text-white font-medium text-sm transition-colors"
            >
              Read the Docs
              <ArrowRight size={16} />
            </Link>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-gray-200 dark:border-gray-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8 flex items-center justify-between text-sm text-gray-500">
          <div className="flex items-center gap-2">
            <Shield size={14} className="text-sentinel-500" />
            <span>Sentinel</span>
          </div>
          <span>MIT License</span>
        </div>
      </footer>
    </div>
  );
}
