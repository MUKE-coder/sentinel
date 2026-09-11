# Sentinel across replicas

This example runs two replicas of one app behind Caddy, which alternates requests between them. The replicas share:

- **Redis**, for Sentinel's counters (`Config.Counters = redisstore.New(client)`). Rate limits and AuthShield lockouts are counted once for the whole deployment.
- **Postgres**, for Sentinel's data (threats, blocks, audit log). Both dashboards show the same data.
- **`Dashboard.SecretKey`**, so a dashboard token from one replica is accepted by the other.

## Run

From this directory (needs Docker with Compose v2):

```sh
docker compose up -d --build
```

## Check that the limits hold across replicas

Each app allows 10 requests per minute per client IP. With in-memory counters, two replicas would allow 20. With shared counters, the 11th request gets 429, whichever replica serves it:

```sh
for i in $(seq 1 12); do curl -s -w " %{http_code}\n" localhost:8080/api/hello; done
```

The responses alternate between `app1` and `app2`. The first 10 return 200, and the rest return 429.

AuthShield locks a client out after 5 failed logins, counted across both replicas:

```sh
for i in $(seq 1 6); do
  curl -s -w " %{http_code}\n" -H 'Content-Type: application/json' \
    -d '{"username":"alice","password":"wrong"}' localhost:8080/api/login
done
```

The first 5 attempts return 401. The 6th returns 429 `AUTH_SHIELD_LOCKED`, even though no single replica saw 5 failures.

Both checks count your address, not Caddy's. The apps trust `X-Forwarded-For` only from Caddy's fixed address (`TRUSTED_PROXIES`).

## Dashboard

Open http://localhost:8080/sentinel/ui and log in as `admin` with `SENTINEL_PASSWORD` (default `change-me-please`). Set `SENTINEL_PASSWORD` and `SENTINEL_SECRET_KEY` before running this anywhere but your own machine.

Clean up with `docker compose down -v`.
