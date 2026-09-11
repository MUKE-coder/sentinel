# Scanning Sentinel with ZAP and sqlmap

`examples/scan-target` is a small app with two deliberate holes, mounted behind Sentinel:

- `GET /api/items?id=` builds its SQL query by string concatenation, so it is injectable.
- `GET /api/search?q=` echoes `q` into HTML without escaping, so it is vulnerable to XSS.

Scan it once with the WAF off, to confirm the holes are real, and once with it blocking, to see what Sentinel stops. **Never deploy the target.**

## Run

From this directory (needs Docker with Compose v2):

```sh
# Baseline: the WAF is off, so sqlmap should find the injection.
SENTINEL_WAF=off docker compose up -d --build target
SENTINEL_WAF=off docker compose run --rm sqlmap
SENTINEL_WAF=off docker compose run --rm zap

# The same scans with the WAF blocking.
SENTINEL_WAF=block docker compose up -d --build target
SENTINEL_WAF=block docker compose run --rm sqlmap
SENTINEL_WAF=block docker compose run --rm zap

docker compose down
```

Reports are written to `reports/`:

- `sqlmap-off/` and `sqlmap-block/` hold sqlmap's session logs.
- `zap-off.html` and `zap-block.html` hold ZAP's alerts.

With the WAF on `block`, open the dashboard at http://localhost:8080/sentinel/ui (password `scan-target-password`, or set `SENTINEL_PASSWORD`). It shows each blocked request, the pattern that matched it, and where the match was.

## Reading the results

- **sqlmap.** Compare what sqlmap reports as injectable with the WAF off and on. When it gets past the WAF with a tamper script or a technique the patterns miss, the request is in its log. Add that payload to `detection/testdata/attacks.tsv` and open an issue.
- **ZAP.** A full scan also sends many requests that aren't attacks. Alerts that remain with the WAF on show what got through. Requests that were blocked but weren't attacks are false positives. Those belong in `detection/testdata/benign.tsv`.

This harness doesn't run in CI, because the scans take minutes and need network access to pull the images. The fast, deterministic check lives in the Go tests: `detection/corpus_test.go` and `attack_regression_test.go`.
