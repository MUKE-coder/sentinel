module.exports=[46122,a=>{a.n(a.i(98421))},43604,a=>{a.n(a.i(46899))},7907,a=>{a.n(a.i(66478))},45019,a=>{a.n(a.i(25284))},42523,a=>{a.n(a.i(43199))},76750,a=>{a.n(a.i(1583))},45648,a=>{"use strict";var b=a.i(17750);let c=a=>{let b=a.replace(/^([A-Z])|[\s-_]+(\w)/g,(a,b,c)=>c?c.toUpperCase():b.toLowerCase());return b.charAt(0).toUpperCase()+b.slice(1)},d=(...a)=>a.filter((a,b,c)=>!!a&&""!==a.trim()&&c.indexOf(a)===b).join(" ").trim();var e={xmlns:"http://www.w3.org/2000/svg",width:24,height:24,viewBox:"0 0 24 24",fill:"none",stroke:"currentColor",strokeWidth:2,strokeLinecap:"round",strokeLinejoin:"round"};let f=(0,b.forwardRef)(({color:a="currentColor",size:c=24,strokeWidth:f=2,absoluteStrokeWidth:g,className:h="",children:i,iconNode:j,...k},l)=>(0,b.createElement)("svg",{ref:l,...e,width:c,height:c,stroke:a,strokeWidth:g?24*Number(f)/Number(c):f,className:d("lucide",h),...k},[...j.map(([a,c])=>(0,b.createElement)(a,c)),...Array.isArray(i)?i:[i]])),g=(a,e)=>{let g=(0,b.forwardRef)(({className:g,...h},i)=>(0,b.createElement)(f,{ref:i,iconNode:e,className:d(`lucide-${c(a).replace(/([a-z0-9])([A-Z])/g,"$1-$2").toLowerCase()}`,`lucide-${a}`,g),...h}));return g.displayName=c(a),g};a.s(["default",()=>g],45648)},13500,a=>{"use strict";a.s(["default",()=>b]);let b=(0,a.i(4039).registerClientReference)(function(){throw Error("Attempted to call the default export of [project]/components/CodeBlock.jsx <module evaluation> from the server, but it's on the client. It's not possible to invoke a client function from the server, it can only be rendered as a Component or passed to props of a Client Component.")},"[project]/components/CodeBlock.jsx <module evaluation>","default")},70858,a=>{"use strict";a.s(["default",()=>b]);let b=(0,a.i(4039).registerClientReference)(function(){throw Error("Attempted to call the default export of [project]/components/CodeBlock.jsx from the server, but it's on the client. It's not possible to invoke a client function from the server, it can only be rendered as a Component or passed to props of a Client Component.")},"[project]/components/CodeBlock.jsx","default")},17924,a=>{"use strict";a.i(13500);var b=a.i(70858);a.n(b)},64939,a=>{"use strict";var b=a.i(81332),c=a.i(45648);let d=(0,c.default)("triangle-alert",[["path",{d:"m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3",key:"wmoenq"}],["path",{d:"M12 9v4",key:"juzpu7"}],["path",{d:"M12 17h.01",key:"p32p05"}]]),e=(0,c.default)("info",[["circle",{cx:"12",cy:"12",r:"10",key:"1mglay"}],["path",{d:"M12 16v-4",key:"1dtifu"}],["path",{d:"M12 8h.01",key:"e9boi3"}]]),f=(0,c.default)("circle-check-big",[["path",{d:"M21.801 10A10 10 0 1 1 17 3.335",key:"yps3ct"}],["path",{d:"m9 11 3 3L22 4",key:"1pflzl"}]]),g=(0,c.default)("circle-x",[["circle",{cx:"12",cy:"12",r:"10",key:"1mglay"}],["path",{d:"m15 9-6 6",key:"1uzhvr"}],["path",{d:"m9 9 6 6",key:"z0biqf"}]]),h=function(){for(var a,b,c=0,d="",e=arguments.length;c<e;c++)(a=arguments[c])&&(b=function a(b){var c,d,e="";if("string"==typeof b||"number"==typeof b)e+=b;else if("object"==typeof b)if(Array.isArray(b)){var f=b.length;for(c=0;c<f;c++)b[c]&&(d=a(b[c]))&&(e&&(e+=" "),e+=d)}else for(d in b)b[d]&&(e&&(e+=" "),e+=d);return e}(a))&&(d&&(d+=" "),d+=b);return d},i={info:{icon:e,container:"bg-blue-50 dark:bg-blue-950/30 border-blue-200 dark:border-blue-800",icon_color:"text-blue-500",title_color:"text-blue-800 dark:text-blue-300"},warning:{icon:d,container:"bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-800",icon_color:"text-amber-500",title_color:"text-amber-800 dark:text-amber-300"},success:{icon:f,container:"bg-green-50 dark:bg-green-950/30 border-green-200 dark:border-green-800",icon_color:"text-green-500",title_color:"text-green-800 dark:text-green-300"},danger:{icon:g,container:"bg-red-50 dark:bg-red-950/30 border-red-200 dark:border-red-800",icon_color:"text-red-500",title_color:"text-red-800 dark:text-red-300"}};function j({type:a="info",title:c,children:d}){let e=i[a],f=e.icon;return(0,b.jsx)("div",{className:h("my-4 rounded-lg border p-4",e.container),children:(0,b.jsxs)("div",{className:"flex items-start gap-3",children:[(0,b.jsx)(f,{size:18,className:h("mt-0.5 flex-shrink-0",e.icon_color)}),(0,b.jsxs)("div",{children:[c&&(0,b.jsx)("p",{className:h("font-semibold text-sm mb-1",e.title_color),children:c}),(0,b.jsx)("div",{className:"text-sm text-gray-700 dark:text-gray-300",children:d})]})]})})}a.s(["default",()=>j],64939)},91650,a=>{"use strict";var b=a.i(81332),c=a.i(17924),d=a.i(64939);function e(){return(0,b.jsxs)(b.Fragment,{children:[(0,b.jsx)("h1",{children:"Getting Started"}),(0,b.jsx)("p",{children:"Sentinel is a production-grade security intelligence SDK for Go applications using the Gin framework. It provides WAF protection, rate limiting, threat detection, AI analysis, and an embedded React dashboard — all mountable with a single function call."}),(0,b.jsx)("h2",{children:"Installation"}),(0,b.jsxs)("p",{children:["Sentinel requires ",(0,b.jsx)("strong",{children:"Go 1.24+"})," and uses pure-Go SQLite (no CGo required)."]}),(0,b.jsx)(c.default,{language:"bash",code:"go get github.com/MUKE-coder/sentinel",showLineNumbers:!1}),(0,b.jsx)("h2",{children:"Quick Start"}),(0,b.jsxs)("p",{children:["The simplest way to use Sentinel is with zero configuration. This gives you an in-memory store, all defaults, and a dashboard at ",(0,b.jsx)("code",{children:"/sentinel/ui"}),"."]}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`package main

import (
    sentinel "github.com/MUKE-coder/sentinel"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

    // Mount Sentinel with zero config — everything works out of the box
    sentinel.Mount(r, nil, sentinel.Config{})

    // Your application routes
    r.GET("/api/hello", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "Hello, World!"})
    })

    r.Run(":8080")
    // Dashboard: http://localhost:8080/sentinel/ui
    // Default login: admin / sentinel
}`}),(0,b.jsxs)(d.default,{type:"info",title:"Zero Config",children:["With ",(0,b.jsxs)("code",{children:["sentinel.Config","{}"]}),", Sentinel uses sensible defaults: in-memory storage, WAF disabled, rate limiting disabled. The dashboard is always available."]}),(0,b.jsx)("h2",{children:"With WAF and Rate Limiting"}),(0,b.jsx)("p",{children:"Enable security features by setting configuration fields:"}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`package main

import (
    "time"

    sentinel "github.com/MUKE-coder/sentinel"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

    sentinel.Mount(r, nil, sentinel.Config{
        Dashboard: sentinel.DashboardConfig{
            Username:  "admin",
            Password:  "my-secure-password",
            SecretKey: "change-this-in-production",
        },

        Storage: sentinel.StorageConfig{
            Driver:        sentinel.SQLite,
            DSN:           "sentinel.db",
            RetentionDays: 90,
        },

        WAF: sentinel.WAFConfig{
            Enabled: true,
            Mode:    sentinel.ModeBlock,
        },

        RateLimit: sentinel.RateLimitConfig{
            Enabled: true,
            ByIP:    &sentinel.Limit{Requests: 100, Window: time.Minute},
        },
    })

    r.GET("/api/users", func(c *gin.Context) {
        c.JSON(200, gin.H{"users": []string{}})
    })

    r.Run(":8080")
}`}),(0,b.jsx)("h2",{children:"What Happens When You Call Mount"}),(0,b.jsxs)("p",{children:[(0,b.jsx)("code",{children:"sentinel.Mount()"})," performs the following in order:"]}),(0,b.jsxs)("ol",{children:[(0,b.jsx)("li",{children:"Initializes the storage backend (SQLite or in-memory)"}),(0,b.jsx)("li",{children:"Runs database migrations"}),(0,b.jsx)("li",{children:"Creates the IP manager for whitelist/blacklist"}),(0,b.jsx)("li",{children:"Sets up the async event pipeline with worker goroutines"}),(0,b.jsx)("li",{children:"Initializes threat profiler, security score engine, geo-locator"}),(0,b.jsx)("li",{children:"Configures alerting (Slack, email, webhook) if enabled"}),(0,b.jsx)("li",{children:"Registers middleware: Auth Shield, WAF, Rate Limiter, Security Headers, Performance"}),(0,b.jsx)("li",{children:"Registers the REST API and WebSocket endpoints"}),(0,b.jsx)("li",{children:"Optionally initializes the AI provider"}),(0,b.jsx)("li",{children:"Serves the embedded React dashboard"}),(0,b.jsx)("li",{children:"Starts background cleanup and score recomputation goroutines"})]}),(0,b.jsxs)(d.default,{type:"warning",title:"Middleware Order Matters",children:["Sentinel registers middleware in a specific order. Mount it ",(0,b.jsx)("strong",{children:"before"})," your application routes so that all routes are protected."]}),(0,b.jsx)("h2",{children:"Project Architecture"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`sentinel/
├── core/           # Shared types, constants, models
├── ai/             # AI provider interface (Claude, OpenAI, Gemini)
├── alerting/       # Alert dispatching (Slack, email, webhook)
├── api/            # REST API server, JWT auth, WebSocket hub
├── detection/      # WAF pattern matching, custom rule engine
├── gorm/           # GORM audit logging plugin
├── intelligence/   # Threat profiling, scoring, anomaly detection
├── middleware/      # Gin middleware (WAF, rate limit, headers, perf)
├── pipeline/       # Async event pipeline (ring buffer, workers)
├── reports/        # Compliance report generators
├── storage/        # Storage interface + implementations
│   ├── memory/     # In-memory store (default)
│   └── sqlite/     # Pure-Go SQLite store
├── ui/             # Embedded React dashboard
├── sentinel.go     # Mount() entry point
└── models.go       # Type aliases from core/`}),(0,b.jsx)("h2",{children:"Storage Backends"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Driver"}),(0,b.jsx)("th",{children:"Config Value"}),(0,b.jsx)("th",{children:"Notes"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"Memory"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.Memory"})}),(0,b.jsx)("td",{children:"Default. No persistence — good for development."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:"SQLite"}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"sentinel.SQLite"})}),(0,b.jsx)("td",{children:"Pure Go (no CGo). Recommended for production."})]})]})]}),(0,b.jsx)("h2",{children:"Testing Your Setup"}),(0,b.jsx)("p",{children:"After starting your application, verify Sentinel is working:"}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Check the dashboard
curl http://localhost:8080/sentinel/ui

# Try a SQL injection attack (should be blocked if WAF is enabled)
curl "http://localhost:8080/api/users?id=1'+OR+'1'='1"

# Check rate limiting headers
curl -v http://localhost:8080/api/users 2>&1 | grep X-RateLimit`}),(0,b.jsx)("h2",{children:"Next Steps"}),(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/configuration",children:"Full Configuration Reference"})," — All available options"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/waf",children:"WAF Configuration"})," — Custom rules and strictness levels"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/rate-limiting",children:"Rate Limiting"})," — Per-IP, per-user, per-route limits"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/the-dashboard",children:"Dashboard"})," — Explore the 13-page security dashboard"]})]})]})}a.s(["default",()=>e,"metadata",0,{title:"Getting Started - Sentinel Docs"}])}];

//# sourceMappingURL=_0a99bffb._.js.map