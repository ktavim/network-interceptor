# network-interceptor

A service that maps the origins a web app depends on and how each one is protected. One request scans the app with two scanners, and the results come back as one list of services per origin, each with a combined verdict and each scanner's own evidence.

| Scanner | Finds | How |
|---|---|---|
| `interceptor` | Origins the browser called during a crawl. Can log in. | Drives Chromium through the app and records every request. |
| `tracer` | Origins named in the app's configs and JS bundles. | Harvests the URLs, resolves the hosts, and probes each URL anonymously. |

Three processes, one database:

| Part | Runs as | Does |
|---|---|---|
| **API** (FastAPI) | `uvicorn api.main:app` | Apps, scans, results, submit, cancel, event streams |
| **interceptor worker** | `python -m worker`, `WORKER_SCANNER=interceptor` | Claims and runs the interceptor job of each scan |
| **tracer worker** | `python -m worker`, `WORKER_SCANNER=tracer` | Claims and runs the tracer job of each scan |
| **PostgreSQL** | your server | Queue and result store; no other broker |

Every scan has one job per scanner and ends when both have run, so it takes a worker of each kind to finish one. With one kind missing, scans stay `running`.

## Install

Requires Python 3.12 and PostgreSQL.

```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt -r requirements-dev.txt
playwright install chromium        # on every machine that runs a worker
```

## Database setup

Create a database, put its URL in `.env`, and apply the migrations:

```powershell
& "C:\Program Files\PostgreSQL\17\bin\createdb.exe" -U postgres -h localhost f35
```

```
# .env
DATABASE_URL=postgresql+asyncpg://user:password@localhost:5432/f35
```

```powershell
alembic upgrade head
```

The API, the workers and Alembic all read the `.env` in the repo root.

## Run

Three terminals in the repo root, each with the virtual environment active:

```powershell
# 1. API
uvicorn api.main:app --host 127.0.0.1 --port 8000
```

```powershell
# 2. interceptor worker
$env:WORKER_SCANNER = "interceptor"
python -m worker
```

```powershell
# 3. tracer worker
$env:WORKER_SCANNER = "tracer"
python -m worker
```

A worker started without `WORKER_SCANNER`, or with any other value, exits with a message. Any number of workers of either kind can run against one database.

Stopping a worker with Ctrl+C (or SIGTERM) puts the jobs it was running back in the queue, and the next worker of that scanner runs them again from the start. To stop a scan for good, cancel it.

Interactive docs are at `http://127.0.0.1:8000/docs`.

## Run a scan

A scan belongs to an app. Create the app, then scan it:

```powershell
$app = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/apps -ContentType "application/json" `
    -Body '{"name": "Practice", "url": "https://practicesoftwaretesting.com", "owner_ad_group": "dev"}'
$scan = Invoke-RestMethod -Method Post -Uri http://127.0.0.1:8000/api/scans -ContentType "application/json" `
    -Body (@{ app_id = $app.id } | ConvertTo-Json)

Invoke-RestMethod "http://127.0.0.1:8000/api/scans/$($scan.scan_id)"            # status and the two jobs
Invoke-RestMethod "http://127.0.0.1:8000/api/scans/$($scan.scan_id)/services"   # combined results
```

The scan body also takes `max_depth` (1 to 10) for the interceptor's crawl.

Scan `status` is one of `queued`, `running`, `completed`, `partial`, `failed`, `cancelled`. A `partial` scan is one where a scanner completed and the other failed; it can't be submitted, and the fix is to rerun it.

## API

All under `/api`, except `/health`.

| Method | Path | Does |
|---|---|---|
| `GET`, `POST` | `/apps` | List the apps; create one (`name`, `url`, `owner_ad_group`) |
| `GET` | `/apps/{id}/scans` | The app's scans |
| `GET` | `/apps/{id}/diff?from=&to=` | What changed between two of the app's scans |
| `POST` | `/scans` | Start a scan (`app_id`, optional `max_depth`); returns `scan_id` |
| `GET` | `/scans` | List scans |
| `GET` | `/scans/{id}` | One scan, with `jobs`, one per scanner |
| `GET` | `/scans/{id}/services` | Services, each with its combined verdict, `found_by` and each scanner's `findings` |
| `GET` | `/scans/{id}/services/{sid}/urls?scanner=` | A service's URL evidence, each row with its `scanner` and `sources` |
| `PATCH` | `/scans/{id}/services/{sid}` | Exclude a service (`excluded`), or fill in an auth method the scanners couldn't tell (`auth_method`) |
| `POST` | `/scans/{id}/submit` | Submit a completed scan |
| `POST` | `/scans/{id}/cancel` | Cancel a scan |
| `GET` | `/scans/{id}/events` | The scan's events as a server-sent event stream; resumes from `Last-Event-ID` |
| `GET` | `/notifications` | Server-sent event stream across all scans |
| `GET` | `/me` | The current user. A stub: there is no real auth flow. |
| `GET` | `/health` | `{"status": "ok"}` |

## Configuration

Everything but the crawl config is read from the environment, or from `.env`.

| Variable | Read by | Default | Purpose |
|---|---|---|---|
| `DATABASE_URL` | all | *(required)* | `postgresql+asyncpg://user:pw@host:5432/db` |
| `CORS_ALLOW_ORIGINS` | API | `http://localhost:4200` | Comma-separated origins the frontend is served from |
| `WORKER_SCANNER` | worker | *(required)* | `interceptor` or `tracer` |
| `SCAN_TIMEOUT_S` | worker | 3600 interceptor, 900 tracer | Hard cap on one job; exceeding it fails the job |
| `CRAWLER_MAX_PARALLEL` | worker | 2 | Jobs one worker runs at once |
| `CRAWLER_CONFIG_PATH` | interceptor worker | `./config.json` | The crawl config below |

**The interceptor's crawl** is set in `config.json`: `max_depth`, `max_clicks_per_page`, `wait_timeout`, `network_idle_timeout`, `form_filling`, `exclude_patterns` and an optional `login` block. `start_url` is always replaced by the scanned app's URL, and `max_depth` by the scan's own when the request gives one. If the file is missing or fails to load, the worker logs it and uses built-in defaults, with no login.

**Logging in:** the `login` block names two environment variables, `username_env` and `password_env`, and the worker reads the credentials from them. They stay in the interceptor worker's environment and are never stored with a scan. The tracer never logs in.

**The tracer's tuning** is read by the **API**, once at startup, and a snapshot goes onto each scan's tracer job. Set these where the API runs, not the worker; a change takes effect for scans requested after the API restarts.

| Variable | Default | Purpose |
|---|---|---|
| `SCAN_NAV_TIMEOUT_MS` | 30000 | Navigation timeout |
| `SCAN_WAIT_AFTER_LOAD_MS` | 5000 | Idle wait for late XHRs, before and after interactions |
| `SCAN_INTERACT_BUDGET_MS` | 8000 | Per-page budget for scrolls, hovers and clicks |
| `SCAN_FOLLOW_LINKS` | false | Discover and crawl same-origin links |
| `SCAN_MAX_PAGES` | 1 | Cap on pages visited |
| `PROBE_TIMEOUT_S` | 5 | Per-URL probe timeout |
| `PROBE_CONCURRENCY` | 10 | Concurrent probes |
| `DNS_TIMEOUT_S` / `DNS_CONCURRENCY` | 3 / 20 | Resolver timeout and concurrency |

## Tests

```powershell
pytest                                   # unit and tracer tests; integration tests skipped
$env:TEST_DATABASE_URL = "postgresql+asyncpg://user:password@localhost:5432/f35_test"
pytest                                   # + the integration tests against that database
python scripts/e2e.py                    # end to end: its own API and both workers, on a local test site
python scripts/e2e.py --slow             # + hard-kills a worker and waits for the reaper (~75s more)
```

`TEST_DATABASE_URL` must be set in the environment; the tests don't read it from `.env`. The integration tests and `e2e.py` migrate and truncate that database, so they refuse any whose name doesn't end in `_test`. The tracer tests and `e2e.py` launch Chromium.

## Layout

```
api/            routes, response models, event streams
core/           database models, enums, the job queue (jobs.py), the cross-scanner merge (merge.py)
crawler/        the interceptor's engine
config_tracer/  the tracer's engine
worker/         __main__.py picks the scanner from WORKER_SCANNER; job.py has one runner per scanner
alembic/        migrations, driven by DATABASE_URL
scripts/e2e.py  end-to-end smoke test
tests/          unit/, tracer/, integration/
```
