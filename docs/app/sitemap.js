import { siteConfig } from '@/lib/siteConfig';

export default function sitemap() {
  const baseUrl = siteConfig.url;

  const staticPages = [
    {
      url: baseUrl,
      lastModified: new Date(),
      changeFrequency: 'weekly',
      priority: 1,
    },
    {
      url: `${baseUrl}/docs/getting-started`,
      lastModified: new Date(),
      changeFrequency: 'weekly',
      priority: 0.9,
    },
    {
      url: `${baseUrl}/docs/configuration`,
      lastModified: new Date(),
      changeFrequency: 'monthly',
      priority: 0.8,
    },
  ];

  const docPages = [
    'waf',
    'rate-limiting',
    'auth-shield',
    'security-headers',
    'threat-intelligence',
    'anomaly-detection',
    'security-score',
    'the-dashboard',
    'performance',
    'alerting',
    'audit-logging',
    'ai-analysis',
    'compliance-reports',
    'api-reference',
  ].map((slug) => ({
    url: `${baseUrl}/docs/${slug}`,
    lastModified: new Date(),
    changeFrequency: 'monthly',
    priority: 0.7,
  }));

  return [...staticPages, ...docPages];
}
