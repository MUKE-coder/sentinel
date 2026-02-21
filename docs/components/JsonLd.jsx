export function FAQSchema({ faqs, questions }) {
  const items = faqs || questions || [];
  const schema = {
    '@context': 'https://schema.org',
    '@type': 'FAQPage',
    mainEntity: items.map((faq) => ({
      '@type': 'Question',
      name: faq.question || faq.q,
      acceptedAnswer: {
        '@type': 'Answer',
        text: faq.answer || faq.a,
      },
    })),
  };

  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }}
    />
  );
}

export function HowToSchema({ name, description, steps }) {
  const schema = {
    '@context': 'https://schema.org',
    '@type': 'HowTo',
    name,
    description,
    step: steps.map((step, i) => ({
      '@type': 'HowToStep',
      position: i + 1,
      name: step.name,
      text: step.text,
    })),
  };

  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }}
    />
  );
}

export function TechArticleSchema({ title, description, url, datePublished, dateModified, authorName, authorUrl }) {
  const schema = {
    '@context': 'https://schema.org',
    '@type': 'TechArticle',
    headline: title,
    description,
    url,
    datePublished: datePublished || '2025-02-20',
    dateModified: dateModified || new Date().toISOString().split('T')[0],
    author: {
      '@type': 'Person',
      name: authorName || 'JB (Muke JohnBaptist)',
      url: authorUrl || 'https://jb.desishub.com/',
    },
    publisher: {
      '@type': 'Organization',
      name: 'Sentinel',
      url: 'https://sentinel-go-sdk.vercel.app',
    },
    proficiencyLevel: 'Beginner',
    inLanguage: 'en',
  };

  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }}
    />
  );
}

export function SpeakableSchema({ url, cssSelectors, cssSelector }) {
  const selectors = cssSelectors || cssSelector || ['h1', '.prose-docs h2', '.prose-docs p:first-of-type'];
  const schema = {
    '@context': 'https://schema.org',
    '@type': 'WebPage',
    url,
    speakable: {
      '@type': 'SpeakableSpecification',
      cssSelector: selectors,
    },
  };

  return (
    <script
      type="application/ld+json"
      dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }}
    />
  );
}
