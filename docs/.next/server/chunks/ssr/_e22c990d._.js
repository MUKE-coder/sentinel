module.exports=[46122,a=>{a.n(a.i(98421))},43604,a=>{a.n(a.i(46899))},7907,a=>{a.n(a.i(66478))},45019,a=>{a.n(a.i(25284))},42523,a=>{a.n(a.i(43199))},76750,a=>{a.n(a.i(1583))},45648,a=>{"use strict";var b=a.i(17750);let c=a=>{let b=a.replace(/^([A-Z])|[\s-_]+(\w)/g,(a,b,c)=>c?c.toUpperCase():b.toLowerCase());return b.charAt(0).toUpperCase()+b.slice(1)},d=(...a)=>a.filter((a,b,c)=>!!a&&""!==a.trim()&&c.indexOf(a)===b).join(" ").trim();var e={xmlns:"http://www.w3.org/2000/svg",width:24,height:24,viewBox:"0 0 24 24",fill:"none",stroke:"currentColor",strokeWidth:2,strokeLinecap:"round",strokeLinejoin:"round"};let f=(0,b.forwardRef)(({color:a="currentColor",size:c=24,strokeWidth:f=2,absoluteStrokeWidth:g,className:h="",children:i,iconNode:j,...k},l)=>(0,b.createElement)("svg",{ref:l,...e,width:c,height:c,stroke:a,strokeWidth:g?24*Number(f)/Number(c):f,className:d("lucide",h),...k},[...j.map(([a,c])=>(0,b.createElement)(a,c)),...Array.isArray(i)?i:[i]])),g=(a,e)=>{let g=(0,b.forwardRef)(({className:g,...h},i)=>(0,b.createElement)(f,{ref:i,iconNode:e,className:d(`lucide-${c(a).replace(/([a-z0-9])([A-Z])/g,"$1-$2").toLowerCase()}`,`lucide-${a}`,g),...h}));return g.displayName=c(a),g};a.s(["default",()=>g],45648)},13500,a=>{"use strict";a.s(["default",()=>b]);let b=(0,a.i(4039).registerClientReference)(function(){throw Error("Attempted to call the default export of [project]/components/CodeBlock.jsx <module evaluation> from the server, but it's on the client. It's not possible to invoke a client function from the server, it can only be rendered as a Component or passed to props of a Client Component.")},"[project]/components/CodeBlock.jsx <module evaluation>","default")},70858,a=>{"use strict";a.s(["default",()=>b]);let b=(0,a.i(4039).registerClientReference)(function(){throw Error("Attempted to call the default export of [project]/components/CodeBlock.jsx from the server, but it's on the client. It's not possible to invoke a client function from the server, it can only be rendered as a Component or passed to props of a Client Component.")},"[project]/components/CodeBlock.jsx","default")},17924,a=>{"use strict";a.i(13500);var b=a.i(70858);a.n(b)},64939,a=>{"use strict";var b=a.i(81332),c=a.i(45648);let d=(0,c.default)("triangle-alert",[["path",{d:"m21.73 18-8-14a2 2 0 0 0-3.48 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.73-3",key:"wmoenq"}],["path",{d:"M12 9v4",key:"juzpu7"}],["path",{d:"M12 17h.01",key:"p32p05"}]]),e=(0,c.default)("info",[["circle",{cx:"12",cy:"12",r:"10",key:"1mglay"}],["path",{d:"M12 16v-4",key:"1dtifu"}],["path",{d:"M12 8h.01",key:"e9boi3"}]]),f=(0,c.default)("circle-check-big",[["path",{d:"M21.801 10A10 10 0 1 1 17 3.335",key:"yps3ct"}],["path",{d:"m9 11 3 3L22 4",key:"1pflzl"}]]),g=(0,c.default)("circle-x",[["circle",{cx:"12",cy:"12",r:"10",key:"1mglay"}],["path",{d:"m15 9-6 6",key:"1uzhvr"}],["path",{d:"m9 9 6 6",key:"z0biqf"}]]),h=function(){for(var a,b,c=0,d="",e=arguments.length;c<e;c++)(a=arguments[c])&&(b=function a(b){var c,d,e="";if("string"==typeof b||"number"==typeof b)e+=b;else if("object"==typeof b)if(Array.isArray(b)){var f=b.length;for(c=0;c<f;c++)b[c]&&(d=a(b[c]))&&(e&&(e+=" "),e+=d)}else for(d in b)b[d]&&(e&&(e+=" "),e+=d);return e}(a))&&(d&&(d+=" "),d+=b);return d},i={info:{icon:e,container:"bg-blue-50 dark:bg-blue-950/30 border-blue-200 dark:border-blue-800",icon_color:"text-blue-500",title_color:"text-blue-800 dark:text-blue-300"},warning:{icon:d,container:"bg-amber-50 dark:bg-amber-950/30 border-amber-200 dark:border-amber-800",icon_color:"text-amber-500",title_color:"text-amber-800 dark:text-amber-300"},success:{icon:f,container:"bg-green-50 dark:bg-green-950/30 border-green-200 dark:border-green-800",icon_color:"text-green-500",title_color:"text-green-800 dark:text-green-300"},danger:{icon:g,container:"bg-red-50 dark:bg-red-950/30 border-red-200 dark:border-red-800",icon_color:"text-red-500",title_color:"text-red-800 dark:text-red-300"}};function j({type:a="info",title:c,children:d}){let e=i[a],f=e.icon;return(0,b.jsx)("div",{className:h("my-4 rounded-lg border p-4",e.container),children:(0,b.jsxs)("div",{className:"flex items-start gap-3",children:[(0,b.jsx)(f,{size:18,className:h("mt-0.5 flex-shrink-0",e.icon_color)}),(0,b.jsxs)("div",{children:[c&&(0,b.jsx)("p",{className:h("font-semibold text-sm mb-1",e.title_color),children:c}),(0,b.jsx)("div",{className:"text-sm text-gray-700 dark:text-gray-300",children:d})]})]})})}a.s(["default",()=>j],64939)},88652,a=>{"use strict";var b=a.i(81332),c=a.i(17924),d=a.i(64939);function e(){return(0,b.jsxs)(b.Fragment,{children:[(0,b.jsx)("h1",{children:"Performance Monitoring"}),(0,b.jsx)("p",{children:"Sentinel automatically tracks per-route latency and throughput using lightweight middleware. Every HTTP request is measured — no manual instrumentation required. Metrics are aggregated in memory and exposed via API endpoints and the built-in dashboard."}),(0,b.jsxs)(d.default,{type:"info",title:"Always On",children:["Performance monitoring is enabled by default when Sentinel is mounted. The middleware adds negligible overhead (nanosecond-precision timing around your handlers). Configure"," ",(0,b.jsx)("code",{children:"PerformanceConfig"})," to tune slow-request thresholds and retention."]}),(0,b.jsx)("h2",{id:"what-gets-tracked",children:"What Gets Tracked"}),(0,b.jsx)("p",{children:"The performance middleware captures the following data points for every request:"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Data Point"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Duration"})}),(0,b.jsxs)("td",{children:["Total time from request received to response written, measured with ",(0,b.jsx)("code",{children:"time.Since"}),"."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"StatusCode"})}),(0,b.jsx)("td",{children:"HTTP status code returned to the client."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"ResponseSize"})}),(0,b.jsx)("td",{children:"Size of the response body in bytes."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Method"})}),(0,b.jsxs)("td",{children:["HTTP method (",(0,b.jsx)("code",{children:"GET"}),", ",(0,b.jsx)("code",{children:"POST"}),", etc.)."]})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"Path"})}),(0,b.jsx)("td",{children:"Request path, used for per-route aggregation."})]})]})]}),(0,b.jsx)("h2",{id:"configuration",children:"Configuration"}),(0,b.jsxs)("p",{children:["Customize performance monitoring through ",(0,b.jsx)("code",{children:"PerformanceConfig"}),". The only tunable field is the slow-request threshold — everything else works out of the box."]}),(0,b.jsx)(c.default,{language:"go",filename:"main.go",code:`import (
    "time"

    sentinel "github.com/MUKE-coder/sentinel"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

    sentinel.Mount(r, nil, sentinel.Config{
        Performance: sentinel.PerformanceConfig{
            SlowRequestThreshold: 2 * time.Second,
        },
    })

    r.GET("/api/data", func(c *gin.Context) {
        c.JSON(200, gin.H{"status": "ok"})
    })

    r.Run(":8080")
}`}),(0,b.jsx)("h3",{children:"PerformanceConfig Reference"}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Field"}),(0,b.jsx)("th",{children:"Type"}),(0,b.jsx)("th",{children:"Default"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsx)("tbody",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"SlowRequestThreshold"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"time.Duration"})}),(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"1 * time.Second"})}),(0,b.jsx)("td",{children:"Requests exceeding this duration are flagged as slow in metrics and the dashboard."})]})})]}),(0,b.jsx)("h2",{id:"metrics",children:"Metrics"}),(0,b.jsx)("p",{children:"Sentinel computes the following aggregate metrics from collected request data. Metrics are maintained per route and system-wide."}),(0,b.jsxs)("table",{children:[(0,b.jsx)("thead",{children:(0,b.jsxs)("tr",{children:[(0,b.jsx)("th",{children:"Metric"}),(0,b.jsx)("th",{children:"Scope"}),(0,b.jsx)("th",{children:"Description"})]})}),(0,b.jsxs)("tbody",{children:[(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"p50"})}),(0,b.jsx)("td",{children:"Per-route / Global"}),(0,b.jsx)("td",{children:"Median latency — 50th percentile of request durations."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"p95"})}),(0,b.jsx)("td",{children:"Per-route / Global"}),(0,b.jsx)("td",{children:"95th percentile latency — captures tail performance."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"p99"})}),(0,b.jsx)("td",{children:"Per-route / Global"}),(0,b.jsx)("td",{children:"99th percentile latency — worst-case excluding extreme outliers."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"errorRate"})}),(0,b.jsx)("td",{children:"Per-route / Global"}),(0,b.jsx)("td",{children:"Percentage of requests returning 5xx status codes."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"throughput"})}),(0,b.jsx)("td",{children:"Per-route / Global"}),(0,b.jsx)("td",{children:"Requests per second over the most recent measurement window."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"avgResponseSize"})}),(0,b.jsx)("td",{children:"Per-route"}),(0,b.jsx)("td",{children:"Average response body size in bytes."})]}),(0,b.jsxs)("tr",{children:[(0,b.jsx)("td",{children:(0,b.jsx)("code",{children:"slowRequests"})}),(0,b.jsx)("td",{children:"Per-route / Global"}),(0,b.jsxs)("td",{children:["Count of requests exceeding ",(0,b.jsx)("code",{children:"SlowRequestThreshold"}),"."]})]})]})]}),(0,b.jsx)("h2",{id:"api",children:"API Endpoints"}),(0,b.jsx)("p",{children:"Performance data is available through two REST endpoints served by the Sentinel dashboard router."}),(0,b.jsx)("h3",{children:"System Overview"}),(0,b.jsx)("p",{children:"Returns a high-level snapshot of system-wide performance metrics."}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:"GET /sentinel/api/performance/overview"}),(0,b.jsx)(c.default,{language:"json",filename:"response",code:`{
    "totalRequests": 48210,
    "avgResponseTime": "12ms",
    "p50": "8ms",
    "p95": "45ms",
    "p99": "120ms",
    "errorRate": 0.023,
    "throughput": 82.5,
    "slowRequests": 37
}`}),(0,b.jsx)("h3",{children:"Per-Route Breakdown"}),(0,b.jsx)("p",{children:"Returns latency, throughput, and error metrics broken down by route."}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:"GET /sentinel/api/performance/routes"}),(0,b.jsx)(c.default,{language:"json",filename:"response",code:`{
    "routes": [
        {
            "method": "GET",
            "path": "/api/users",
            "totalRequests": 12400,
            "avgDuration": "15ms",
            "p50": "10ms",
            "p95": "52ms",
            "p99": "140ms",
            "errorRate": 0.01,
            "throughput": 21.3,
            "avgResponseSize": 2048,
            "slowRequests": 8
        },
        {
            "method": "POST",
            "path": "/api/orders",
            "totalRequests": 3500,
            "avgDuration": "85ms",
            "p50": "60ms",
            "p95": "210ms",
            "p99": "450ms",
            "errorRate": 0.04,
            "throughput": 6.1,
            "avgResponseSize": 512,
            "slowRequests": 12
        }
    ]
}`}),(0,b.jsx)("h2",{id:"dashboard",children:"Dashboard"}),(0,b.jsxs)("p",{children:["The Sentinel dashboard includes a dedicated ",(0,b.jsx)("strong",{children:"Performance"})," page that displays a sortable route metrics table. Each row shows a route's method, path, request count, latency percentiles (p50 / p95 / p99), error rate, throughput, and slow request count. Use the table to identify your slowest and most error-prone endpoints at a glance."]}),(0,b.jsx)(d.default,{type:"success",title:"Real-Time Updates",children:"The performance dashboard refreshes automatically. Metrics update as new requests are processed — no manual polling required."}),(0,b.jsx)("h2",{id:"slow-request-detection",children:"Slow Request Detection"}),(0,b.jsxs)("p",{children:["Any request whose duration exceeds ",(0,b.jsx)("code",{children:"SlowRequestThreshold"})," is flagged as a slow request. Slow requests are counted separately in both the system overview and per-route metrics, making it easy to spot routes that need optimization."]}),(0,b.jsx)(c.default,{language:"go",showLineNumbers:!1,code:`// Flag requests taking longer than 500ms
Performance: sentinel.PerformanceConfig{
    SlowRequestThreshold: 500 * time.Millisecond,
}

// Flag requests taking longer than 3 seconds
Performance: sentinel.PerformanceConfig{
    SlowRequestThreshold: 3 * time.Second,
}`}),(0,b.jsxs)(d.default,{type:"warning",title:"Threshold Tuning",children:["Set the threshold based on your application's performance expectations. A value that is too low floods the slow request count with noise; too high and genuinely slow endpoints go unnoticed. Start with ",(0,b.jsx)("code",{children:"1 * time.Second"})," and adjust after observing real traffic."]}),(0,b.jsx)("h2",{id:"how-it-works",children:"How It Works"}),(0,b.jsx)("p",{children:"Performance monitoring is implemented as Gin middleware that wraps every request handler."}),(0,b.jsxs)("ol",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Before handler"})," — The middleware records ",(0,b.jsx)("code",{children:"time.Now()"})," as the start time."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Handler executes"})," — The request is passed through to your route handler via ",(0,b.jsx)("code",{children:"c.Next()"}),"."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"After handler"})," — The middleware computes the duration (",(0,b.jsx)("code",{children:"time.Since(start)"}),"), captures the status code and response size, and builds a ",(0,b.jsx)("code",{children:"PerformanceMetric"})," struct."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Pipeline emission"})," — The metric is emitted to Sentinel's async event pipeline via a non-blocking send. This decouples metric aggregation from request handling, adding no meaningful latency."]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("strong",{children:"Aggregation"})," — A pipeline handler receives the metric and updates in-memory aggregates: increments request counters, inserts the duration into a percentile sketch, updates error counts, and checks against ",(0,b.jsx)("code",{children:"SlowRequestThreshold"}),"."]})]}),(0,b.jsx)(c.default,{language:"bash",showLineNumbers:!1,code:`# Request lifecycle with performance monitoring:
#
# Request ──> Middleware records start time
#                 │
#                 v
#             c.Next() ──> Your handler runs
#                 │
#                 v
#             Compute duration, status, size
#                 │
#                 v
#             Emit PerformanceMetric to pipeline (non-blocking)
#                 │
#                 v
#             Response sent to client
#
# Pipeline (async):
#   PerformanceMetric ──> Update aggregates
#                             ├── Percentile sketch (p50/p95/p99)
#                             ├── Error rate counter
#                             ├── Throughput counter
#                             └── Slow request check`}),(0,b.jsx)(d.default,{type:"info",title:"Zero Latency Impact",children:"The metric emission is non-blocking. If the pipeline buffer is full, the metric is dropped rather than stalling the response. Under normal operation, no metrics are lost."}),(0,b.jsx)("h2",{children:"Next Steps"}),(0,b.jsxs)("ul",{children:[(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/configuration",children:"Configuration Reference"})," — Full PerformanceConfig field reference"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/anomaly-detection",children:"Anomaly Detection"})," — Detect unusual traffic patterns using behavioral baselines"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/rate-limiting",children:"Rate Limiting"})," — Throttle excessive traffic before it impacts performance"]}),(0,b.jsxs)("li",{children:[(0,b.jsx)("a",{href:"/docs/the-dashboard",children:"Dashboard"})," — Explore the Performance page and other dashboard features"]})]})]})}a.s(["default",()=>e,"metadata",0,{title:"Performance Monitoring - Sentinel Docs"}])}];

//# sourceMappingURL=_e22c990d._.js.map