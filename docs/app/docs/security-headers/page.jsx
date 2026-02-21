import CodeBlock from '@/components/CodeBlock';
import Callout from '@/components/Callout';
import { FAQSchema, TechArticleSchema, SpeakableSchema } from '@/components/JsonLd';

export const metadata = {
  title: 'Security Headers - Sentinel Docs',
  description:
    'Configure HTTP security headers in Sentinel including CSP, HSTS, X-Frame-Options, and Referrer-Policy for your Go/Gin application.',
  alternates: {
    canonical: 'https://sentinel-go-sdk.vercel.app/docs/security-headers',
  },
  openGraph: {
    title: 'Security Headers - Sentinel Docs',
    description:
      'Configure HTTP security headers in Sentinel including CSP, HSTS, X-Frame-Options, and Referrer-Policy for your Go/Gin application.',
    url: 'https://sentinel-go-sdk.vercel.app/docs/security-headers',
    siteName: 'Sentinel',
    type: 'article',
  },
};

export default function SecurityHeaders() {
  return (
    <>
      <FAQSchema
        questions={[
          {
            q: 'What security headers does Sentinel set by default?',
            a: 'Sentinel automatically sets three headers out of the box: X-Frame-Options (DENY), X-Content-Type-Options (nosniff), and Referrer-Policy (strict-origin-when-cross-origin). These are active with zero configuration when you call sentinel.Mount().',
          },
          {
            q: 'How do I enable HSTS in Sentinel?',
            a: 'Set StrictTransportSecurity to true in your HeaderConfig. Sentinel emits the header with max-age=63072000 (2 years), includeSubDomains, and preload directives. Only enable HSTS when your site and all subdomains fully support HTTPS.',
          },
          {
            q: 'How do I configure Content-Security-Policy (CSP) in Sentinel?',
            a: 'Set the ContentSecurityPolicy string field in HeaderConfig to your desired policy, for example "default-src \'self\'; script-src \'self\'". Sentinel does not set a default CSP because every application has different resource requirements.',
          },
          {
            q: 'Are Sentinel security headers enabled by default?',
            a: 'Yes. Unlike most Sentinel features, security headers are active automatically when you call sentinel.Mount(). X-Frame-Options, X-Content-Type-Options, and Referrer-Policy are injected into every response with no configuration needed.',
          },
        ]}
      />
      <TechArticleSchema
        title="Security Headers - Sentinel Docs"
        description="Configure HTTP security headers in Sentinel including CSP, HSTS, X-Frame-Options, and Referrer-Policy for your Go/Gin application."
        url="https://sentinel-go-sdk.vercel.app/docs/security-headers"
      />
      <SpeakableSchema
        url="https://sentinel-go-sdk.vercel.app/docs/security-headers"
        cssSelector={['h1', 'h2', '.callout']}
      />

      <h1>Security Headers</h1>
      <p>
        Sentinel automatically injects HTTP security headers into every response. The headers
        middleware is <strong>enabled by default</strong> when you call{' '}
        <code>sentinel.Mount()</code>, so your application gets a strong security baseline with
        zero configuration.
      </p>

      <Callout type="success" title="Enabled by Default">
        Unlike most Sentinel features, security headers are active out of the box. Every response
        from your application will include <code>X-Frame-Options</code>,{' '}
        <code>X-Content-Type-Options</code>, and <code>Referrer-Policy</code> headers without any
        configuration.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  AVAILABLE HEADERS                                                  */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="available-headers">Available Headers</h2>
      <p>
        The <code>HeaderConfig</code> struct controls which security headers are injected and their
        values. All fields are optional — sensible defaults are applied automatically.
      </p>

      <table>
        <thead>
          <tr>
            <th>Header</th>
            <th>Config Field</th>
            <th>Type</th>
            <th>Default</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>Content-Security-Policy</code></td>
            <td><code>ContentSecurityPolicy</code></td>
            <td><code>string</code></td>
            <td><em>(not set)</em></td>
          </tr>
          <tr>
            <td><code>Strict-Transport-Security</code></td>
            <td><code>StrictTransportSecurity</code></td>
            <td><code>bool</code></td>
            <td><code>false</code></td>
          </tr>
          <tr>
            <td><code>X-Frame-Options</code></td>
            <td><code>XFrameOptions</code></td>
            <td><code>string</code></td>
            <td><code>"DENY"</code></td>
          </tr>
          <tr>
            <td><code>X-Content-Type-Options</code></td>
            <td><code>XContentTypeOptions</code></td>
            <td><code>bool</code></td>
            <td><code>true</code> (emits <code>"nosniff"</code>)</td>
          </tr>
          <tr>
            <td><code>Referrer-Policy</code></td>
            <td><code>ReferrerPolicy</code></td>
            <td><code>string</code></td>
            <td><code>"strict-origin-when-cross-origin"</code></td>
          </tr>
          <tr>
            <td><code>Permissions-Policy</code></td>
            <td><code>PermissionsPolicy</code></td>
            <td><code>string</code></td>
            <td><em>(not set)</em></td>
          </tr>
        </tbody>
      </table>

      {/* ------------------------------------------------------------------ */}
      {/*  CONFIGURATION                                                      */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="configuration">Configuration</h2>
      <p>
        Pass a <code>HeaderConfig</code> inside your <code>sentinel.Config</code> to customise
        the headers. Fields you omit keep their defaults.
      </p>

      <CodeBlock
        language="go"
        filename="main.go"
        code={`package main

import (
    sentinel "github.com/MUKE-coder/sentinel"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

    sentinel.Mount(r, nil, sentinel.Config{
        Headers: sentinel.HeaderConfig{
            ContentSecurityPolicy:   "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
            StrictTransportSecurity: true,
            XFrameOptions:           "SAMEORIGIN",
            XContentTypeOptions:     true,
            ReferrerPolicy:          "strict-origin-when-cross-origin",
            PermissionsPolicy:       "camera=(), microphone=(), geolocation=()",
        },
    })

    r.GET("/api/data", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })

    r.Run(":8080")
}`}
      />

      <p>
        To use only the defaults (X-Frame-Options, X-Content-Type-Options, and Referrer-Policy),
        you do not need to set the <code>Headers</code> field at all:
      </p>

      <CodeBlock
        language="go"
        showLineNumbers={false}
        code={`// Defaults are applied automatically — these three headers are set:
//   X-Frame-Options: DENY
//   X-Content-Type-Options: nosniff
//   Referrer-Policy: strict-origin-when-cross-origin
sentinel.Mount(r, nil, sentinel.Config{})`}
      />

      <Callout type="info" title="Disabling Security Headers">
        If you need to disable the headers middleware entirely (for example, because a reverse
        proxy already sets them), pass <code>Enabled</code> as a <code>false</code> pointer:
      </Callout>

      <CodeBlock
        language="go"
        showLineNumbers={false}
        code={`disabled := false
sentinel.Mount(r, nil, sentinel.Config{
    Headers: sentinel.HeaderConfig{
        Enabled: &disabled,
    },
})`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  WHAT EACH HEADER DOES                                              */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="what-each-header-does">What Each Header Does</h2>

      <h3>Content-Security-Policy (CSP)</h3>
      <p>
        Controls which resources (scripts, styles, images, fonts, etc.) the browser is allowed to
        load. A well-configured CSP is one of the most effective defenses against cross-site
        scripting (XSS) attacks because it prevents the browser from executing injected scripts
        even if they make it into the HTML.
      </p>
      <CodeBlock
        language="go"
        showLineNumbers={false}
        code={`ContentSecurityPolicy: "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:"`}
      />
      <Callout type="warning" title="CSP Not Set by Default">
        Sentinel does not set a default CSP because every application has different resource
        requirements. A restrictive policy applied blindly would break most frontends. Define a CSP
        that matches your application's needs.
      </Callout>

      <h3>Strict-Transport-Security (HSTS)</h3>
      <p>
        Tells browsers to only access your site over HTTPS for a specified duration. This prevents
        protocol downgrade attacks and cookie hijacking. When enabled, Sentinel sets:
      </p>
      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`}
      />
      <p>
        The <code>max-age=63072000</code> value (2 years) with <code>includeSubDomains</code> and{' '}
        <code>preload</code> follows current best practices. Only enable this when your site is
        fully served over HTTPS.
      </p>

      <Callout type="danger" title="HSTS Is Sticky">
        Once a browser receives an HSTS header, it will refuse to connect over HTTP for the
        entire <code>max-age</code> duration. Only set{' '}
        <code>StrictTransportSecurity: true</code> when you are certain your site and all
        subdomains support HTTPS.
      </Callout>

      <h3>X-Frame-Options</h3>
      <p>
        Prevents your pages from being embedded in <code>&lt;iframe&gt;</code>,{' '}
        <code>&lt;frame&gt;</code>, or <code>&lt;object&gt;</code> elements on other sites. This
        is the primary defense against clickjacking attacks, where an attacker overlays your UI
        with a transparent iframe to trick users into clicking hidden elements.
      </p>
      <table>
        <thead>
          <tr>
            <th>Value</th>
            <th>Behavior</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>"DENY"</code></td>
            <td>Page cannot be framed by any site, including your own. <strong>(Default)</strong></td>
          </tr>
          <tr>
            <td><code>"SAMEORIGIN"</code></td>
            <td>Page can only be framed by pages on the same origin.</td>
          </tr>
        </tbody>
      </table>

      <h3>X-Content-Type-Options</h3>
      <p>
        Prevents browsers from MIME-sniffing a response away from the declared{' '}
        <code>Content-Type</code>. Without this header, a browser might interpret a text file as
        JavaScript or HTML, enabling attacks where an attacker uploads a file with a misleading
        extension. The only valid value is <code>"nosniff"</code>, which is always set when this
        option is <code>true</code>.
      </p>

      <h3>Referrer-Policy</h3>
      <p>
        Controls how much referrer information is sent when navigating away from your site. The
        default <code>"strict-origin-when-cross-origin"</code> sends the full URL for same-origin
        requests but only the origin (no path or query string) for cross-origin requests, and
        nothing when downgrading from HTTPS to HTTP. This protects sensitive URL parameters from
        leaking to third parties.
      </p>
      <table>
        <thead>
          <tr>
            <th>Value</th>
            <th>Behavior</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><code>"no-referrer"</code></td>
            <td>Never send referrer information.</td>
          </tr>
          <tr>
            <td><code>"same-origin"</code></td>
            <td>Only send referrer for same-origin requests.</td>
          </tr>
          <tr>
            <td><code>"strict-origin-when-cross-origin"</code></td>
            <td>Full URL for same-origin, origin only for cross-origin, nothing on downgrade. <strong>(Default)</strong></td>
          </tr>
        </tbody>
      </table>

      <h3>Permissions-Policy</h3>
      <p>
        Controls which browser features and APIs your site can use (camera, microphone,
        geolocation, payment, etc.). This limits the damage if an attacker injects code into
        your page — even injected scripts cannot access restricted APIs.
      </p>
      <CodeBlock
        language="go"
        showLineNumbers={false}
        code={`// Disable camera, microphone, and geolocation for all origins
PermissionsPolicy: "camera=(), microphone=(), geolocation=()"

// Allow geolocation only from your own origin
PermissionsPolicy: "camera=(), microphone=(), geolocation=(self)"`}
      />

      {/* ------------------------------------------------------------------ */}
      {/*  TESTING                                                            */}
      {/* ------------------------------------------------------------------ */}

      <h2 id="testing">Testing with curl</h2>
      <p>
        Use <code>curl -v</code> to verify that security headers are present on responses from
        your application.
      </p>

      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# Inspect response headers
curl -v http://localhost:8080/api/data 2>&1 | grep -i "x-frame\\|x-content\\|referrer\\|content-security\\|strict-transport\\|permissions-policy"

# Expected output (with full configuration):
# < X-Frame-Options: SAMEORIGIN
# < X-Content-Type-Options: nosniff
# < Referrer-Policy: strict-origin-when-cross-origin
# < Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'
# < Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
# < Permissions-Policy: camera=(), microphone=(), geolocation=()`}
      />

      <CodeBlock
        language="bash"
        showLineNumbers={false}
        code={`# With default configuration (no Headers config), you will see:
curl -v http://localhost:8080/api/data 2>&1 | grep -i "x-frame\\|x-content\\|referrer"

# < X-Frame-Options: DENY
# < X-Content-Type-Options: nosniff
# < Referrer-Policy: strict-origin-when-cross-origin`}
      />

      <Callout type="info" title="Check All Headers at Once">
        Run <code>curl -I http://localhost:8080/api/data</code> to see all response headers
        in a compact format. The <code>-I</code> flag sends a HEAD request and prints only
        the headers.
      </Callout>

      {/* ------------------------------------------------------------------ */}
      {/*  NEXT STEPS                                                         */}
      {/* ------------------------------------------------------------------ */}

      <h2>Next Steps</h2>
      <ul>
        <li><a href="/docs/waf">WAF</a> -- Protect against SQL injection, XSS, and other attacks at the request level</li>
        <li><a href="/docs/rate-limiting">Rate Limiting</a> -- Throttle abusive traffic before it reaches your handlers</li>
        <li><a href="/docs/configuration">Configuration Reference</a> -- Full list of all Sentinel configuration options</li>
      </ul>
    </>
  );
}
