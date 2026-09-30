# Merging config-tracer into network-interceptor

**Status:** proposal, 2026-09-30. No code has changed yet. The merged service starts on a fresh database; both existing databases hold only dev data and are dropped.

## 1. Goal

One request (`POST /api/scans`) runs both scanners on the same target. Results land in one database and come back as one list of services per origin, with each scanner's evidence kept.

Out of scope for this plan:

- Carrying over existing data. Both databases hold only dev data, so the merged service starts on a fresh database (§7, step 3).
- Changing either scanner's detection logic.

## 2. Starting point

| | network-interceptor | config-tracer |
|---|---|---|
| Finds | Origins the browser called during a crawl. Can log in. | Origins named in the app's configs and JS bundles, then probed anonymously. |
| API | Apps, scans, submit, cancel, exclusions, manual auth fix, diff, SSE. Frontend on `:4200`. | Request a scan, read the results. |
| Queue | `scans` table. Heartbeat lease (60 s), reaper, cancel. | `scans` table. Claim-age expiry (30 min), attempts and requeue. |
| IDs | Hex strings | UUID scans, BIGINT services and URLs |
| Scan status | `queued`, `running`, `completed`, `failed`, `cancelled` | `pending`, `running`, `completed`, `failed` |
| Service key | `(scheme, host, port)`, effective port | Same |
| Per-origin rule | Worst URL wins, by `_AUTH_RANK` | Worst URL wins, by `_VERDICT_PRECEDENCE`, in a different order (§4.3) |
| Settings | `config.json` read by the worker, plus `max_depth` per request | Environment, snapshotted onto each scan |
| Database | `network-interceptor` | `config_tracer_api` |
| Python | 3.12 | 3.12+ |

## 3. Target architecture

```
frontend ──► API (network-interceptor/api) ──► 1 scans row + 1 scan_jobs row per scanner
                                                  │
                  ┌───────────────────────────────┴───────────────────────────────┐
     worker, WORKER_SCANNER=network                                  worker, WORKER_SCANNER=config
     claims scanner='network' jobs                                   claims scanner='config' jobs
     runs crawler.Mapper                                             runs config_tracer.pipeline.run_scan
                  └──────────────► urls, service_findings, services ◄─────────────┘
                                   (the last job to finish sets the scan's final status)
```

- One repo (network-interceptor), one new database, one API.
- Postgres stays the queue. The API never calls a worker; it inserts job rows.
- config-tracer's engine (crawl, extract, resolve, probe, report) moves in as a library. Its API, database layer, worker and migrations are retired.
- Both workers use the same image and entry point. `WORKER_SCANNER` picks which jobs a worker claims, so the two can be scaled independently.

Repo layout after the merge:

```
api/            existing routes, extended (§6)
core/
  db.py         + ScanJobRow, ServiceFindingRow
  enums.py      combined AuthMethod; new Scanner and JobStatus
  jobs.py       NEW: claim, heartbeat, reap and finish on scan_jobs, plus finalize_scan (replaces worker/queue.py)
  merge.py      NEW: combines the scanners' findings into one service verdict
  translate.py  + config_report_to_rows
crawler/        network scanner engine, unchanged
config_tracer/  config scanner engine, moved in (everything outside api/, db/ and worker.py)
worker/         __main__.py dispatches on WORKER_SCANNER; job.py has one runner per scanner
```

## 4. Unified schema

### 4.1 Vocabulary

`AuthMethod` becomes the union of both scanners' values:

| Value | Produced by | Severity | Note |
|---|---|---|---|
| `ntlm` | both | blocker | |
| `basic` | both | blocker | |
| `other` | both | blocker | |
| `negotiate` | both | review | |
| `unknown` | both | review | network: a tag outside the vocabulary. config: the server answered with something unclassifiable. |
| `no_response` | both | review | |
| `dns_failed` | config | review | **New.** network-interceptor reports a DNS failure as `no_response` with `failure_reason = net::ERR_NAME_NOT_RESOLVED`. |
| `kerberos` | network | cleared | |
| `bearer` | both | cleared | |
| `oauth` | both | cleared | |
| `login_redirect` | config | cleared | **New.** |
| `api_key` | network | cleared | |
| `unauthenticated` | both | cleared | |

This has to come first. `tag_to_auth_method` maps any value it doesn't know to `unknown`, so without it every `login_redirect` and `dns_failed` from config-tracer would silently become `unknown` with severity review.

Because the schema starts fresh, every column that holds one of these vocabularies gets a CHECK constraint listing its values: the auth method, severity, scanner and status columns. This is what config-tracer does today (`native_enum=False, create_constraint=True`). Adding a value then takes a one-line migration.

The constraint only catches values that skip `tag_to_auth_method`, because that function turns any unrecognized tag into `unknown` before it reaches the database. That fallback stays in the network path, where it's deliberate. The config path must convert with `AuthMethod(value)`, which raises on an unknown value, and never go through `tag_to_auth_method`. A value missing from the combined vocabulary then fails loudly instead of becoming `unknown`.

New enums: `Scanner` (`network`, `config`) and `JobStatus` (`queued`, `running`, `completed`, `failed`, `cancelled`). `ScanStatus` gains `partial`.

### 4.2 Tables

`apps`, `submissions` and `scan_events` are unchanged.

#### `scans` (changed): the parent scan, one per request

| Column | Notes |
|---|---|
| `id`, `app_id`, `name`, `url`, `started_by`, `started_at`, `completed_at`, `error`, `cancel_requested_at` | As in network-interceptor today |
| `status` | Derived from the scan's jobs (§4.4). Adds `partial`. |

Compared with today's table, `worker_id`, `heartbeat_at` and `pages_crawled` move to `scan_jobs`, and `max_depth` moves into the network job's `settings`.

`cancel_requested_at` stays on `scans` because a cancel applies to the whole scan. Each job's heartbeat reads it.

#### `scan_jobs` (new): one per scanner per scan; this is the queue

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | Hex UUID, like the other IDs |
| `scan_id` | FK `scans`, `ON DELETE CASCADE` | |
| `scanner` | String, CHECK in (`network`, `config`) | |
| `status` | String | `JobStatus` |
| `settings` | JSONB, NOT NULL | Snapshot taken at request time. Never holds credentials. |
| `attempts` | Integer, default 0 | |
| `worker_id`, `heartbeat_at` | | Moved from `scans` |
| `error` | Text | |
| `created_at`, `started_at`, `completed_at` | timestamptz | |
| `pages_crawled` | Integer, nullable | |

Constraints: `UNIQUE (scan_id, scanner)`, and an index on `(scanner, status, created_at)` for the claim query.

Settings snapshots:

- **network:** `{"max_depth": …}` in the first version. The worker still merges it onto `config.json`, as it does today.
- **config:** `ScanSettings` built from the API's environment and dumped to JSON, as config-tracer does today.

Login credentials stay in the worker's environment and never go into a snapshot.

#### `services` (same columns, new meaning): one row per origin per scan, combined across scanners

| Column | Meaning after the merge |
|---|---|
| `id`, `scan_id`, `scheme`, `host`, `port` | Unchanged. `UNIQUE (scan_id, scheme, host, port)` becomes the merge key. |
| `auth_method`, `severity` | The combined verdict (§4.3) |
| `evidence_url_id` | The evidence URL of the finding that won |
| `request_count` | URL rows from both scanners |
| `ips` | Union of both scanners' addresses. NULL only when neither resolved the host. |
| `excluded` | Unchanged. Set only by users, never by a worker. |

#### `service_findings` (new): each scanner's own verdict for an origin

| Column | Notes |
|---|---|
| `service_id` | FK `services`, `ON DELETE CASCADE`; part of the PK |
| `scanner` | Part of the PK |
| `auth_method` | This scanner's per-origin verdict, computed by its own rule |
| `evidence_url_id` | FK `urls`, `DEFERRABLE INITIALLY DEFERRED`, for the same reason as `services.evidence_url_id` |
| `url_count` | |

The API's `found_by` field lists the scanners that have a row here.

#### `urls` (changed): evidence rows from both scanners

| Column | Change |
|---|---|
| `scanner` | **New**, NOT NULL |
| `sources` | **New**, TEXT[], default `'{}'`. Filled only by the config scanner, with its provenance strings (`network:`, `js:`, `dom:`, `redirect:`, `synthesized:`). |
| Everything else | Unchanged |

How config-tracer's `UrlEvidence` maps onto `urls`:

| `urls` column | From config-tracer | Note |
|---|---|---|
| `url` | `url`, passed through `strip_url` | network-interceptor strips query, fragment and userinfo when it captures a request. config-tracer stores URLs verbatim, and config URLs can carry keys in their query strings. |
| `method` | `http_method` (`HEAD` or `GET`); `''` for `dns_failed` | |
| `status_code` | `status_code`; 0 when None | network-interceptor's convention: 0 plus `failure_reason` |
| `failure_reason` | `error` | |
| `auth_method` | `detected_method` | |
| `auth_challenge` | `www_authenticate` | |
| `redirect_url` | `location`, resolved against `url`, then passed through `strip_url` | network-interceptor stores it resolved and stripped. config-tracer stores it raw, and it's often relative. |
| `resource_type` | `'probe'` | Lets the UI tell a probe apart from a captured request |
| `page_url` | `''` | The provenance is in `sources` |
| `sent_auth_scheme` | NULL | The probes are anonymous |
| `sources` | `sources` | |

### 4.3 Merge rules

Each scanner keeps its own per-origin rule. The two orderings disagree in two places, on purpose:

| Value | network-interceptor (`_AUTH_RANK`) | config-tracer (`_VERDICT_PRECEDENCE`) |
|---|---|---|
| `no_response` | Lowest: any answer beats no answer. Requests the browser aborted (`net::ERR_ABORTED`) are common noise. | Above `unauthenticated`: a probe that timed out is a URL nobody saw, and an open sibling must not hide it. |
| `unknown` | Above every cleared scheme | Below `bearer`, `oauth` and `login_redirect` |

Each choice is right for the scanner that makes it, so neither ordering changes. The merge only combines the two scanners' findings for an origin.

To compute a service's combined verdict:

1. **One finding:** that finding is the verdict.
2. **Two findings:** apply these refinements first.
   - If one finding is `negotiate` and the other is `kerberos` or `ntlm`, drop the `negotiate`. It's the same SPNEGO challenge; the network scanner saw which mechanism was used, and the anonymous probe can't.
   - If config says `dns_failed` but the network finding has IPs, drop the `dns_failed`. The lookup worked for the other scanner.
   - Then take the finding that ranks higher in the order below. On a tie, take the network finding, since observed traffic beats a probe.
3. Set `severity = severity_for(verdict)`, and set `evidence_url_id` to the winning finding's evidence.

Cross-scanner order, highest first:

`ntlm` > `basic` > `other` > `negotiate` > `unknown` > `no_response` > `dns_failed` > `kerberos` > `bearer` > `oauth` > `login_redirect` > `api_key` > `unauthenticated`

Every blocker ranks above every review value, and every review value above every cleared one. So the combined severity is never lower than either finding's.

`core/merge.py` is a pure function: findings in, verdict out. It runs every time a job finishes, over all of the scan's services, so one scanner's results show up while the other is still running. It never runs after the scan's final status is set, so it can't overwrite a manual auth fix; PATCH works only on completed scans.

### 4.4 Scan status

The parent's status is derived from its jobs:

| Jobs | `scans.status` |
|---|---|
| All queued | `queued` |
| Otherwise, any queued or running | `running` |
| All completed | `completed` |
| At least one completed, the rest failed | `partial` |
| All failed | `failed` |
| Cancel requested and every job finished | `cancelled` |

What follows from this:

- A `partial` scan can't be submitted. `submit_scan` already requires `completed`.
- A `partial` scan doesn't count as the latest completed scan for editing, because `_latest_completed_scan_id` filters on `completed`.
- `derive_exposure_state` treats `partial` like `failed` (D2).

## 5. Worker and queue

The queue keeps network-interceptor's design (heartbeat, cancel, reaper) but moves it from `scans` to `scan_jobs`:

- **`claim_next(scanner)`:** today's statement, run against `scan_jobs` and filtered by scanner, with `SKIP LOCKED`. The claim sets the job to `running`, and sets the scan to `running` if it was still `queued`.
- **`heartbeat`:** `UPDATE scan_jobs … FROM scans … RETURNING scans.cancel_requested_at`. One statement, as today.
- **`reap_stale`:** runs on `scan_jobs`. Each reaped job goes through `finalize_scan`.
- **`finish`:** ends a job, then calls `finalize_scan` in the same transaction.

`finalize_scan(scan_id)` runs in the transaction that ends any job, whether it completed, failed, was cancelled or was reaped:

1. Lock the scan row with `FOR NO KEY UPDATE`, not `FOR UPDATE`. The other job's event inserts take `FOR KEY SHARE` on the scan through the `scan_events` foreign key, and a plain `FOR UPDATE` would block on them. This is the same reason `claim_next` uses `key_share` today.
2. Recompute the scan's services (§4.3).
3. If every job has finished, set `scans.status` and `completed_at` (§4.4), emit `blocker_found` for the combined blockers, then emit the terminal event.

The lock order stays as `core/events.py` documents it: the scan row first, then events. Two workers emitting events for one scan are already safe, because `emit_event` serializes `seq` with a per-scan advisory lock.

Runners in `worker/job.py`:

- **network:** today's `run_scan_job`. It writes a finding plus `urls` rows with `scanner='network'`, instead of whole services.
- **config:** `asyncio.wait_for(config_tracer.pipeline.run_scan([scans.url], ScanSettings(**job.settings)), timeout)`, then `translate.config_report_to_rows`, then the same write path. It emits `auth_detected` per service, as the network crawler does. It keeps config-tracer's hard timeout (900 s). The network runner has no timeout today (D6).

Retries: network-interceptor fails a job whose worker vanished, while config-tracer requeued such a job up to 3 attempts. The first version keeps network-interceptor's behavior. The `attempts` column is ready if retries are wanted later (D3).

Events:

| Event | When | Payload |
|---|---|---|
| `scan_started` | Unchanged | Unchanged |
| `job_started` | A worker claims a job | `{scanner}` |
| `auth_detected` | Unchanged | Adds `scanner` |
| `job_completed` / `job_failed` | A job ends | `{scanner, services}` or `{scanner, error}` |
| `blocker_found` | Moves to `finalize_scan`; emitted once per combined blocker | Unchanged |
| `scan_completed` | The last job ends and the status is `completed` or `partial` | Adds `{partial, failed_scanners}` |
| `scan_failed` | The status is `failed` or `cancelled` | Unchanged |

The terminal events are still `scan_completed` and `scan_failed`, so `TERMINAL_EVENTS` and the SSE streams keep working. A partial scan ends its stream with `scan_completed` and `partial: true`.

## 6. API changes

Everything is additive except the new status value.

| Endpoint | Change |
|---|---|
| `POST /api/scans` | Optional `scanners` field (default: both) creates one job per scanner. The response is unchanged. |
| `GET /api/scans`, `GET /api/apps/{id}/scans` | `status` can be `partial` |
| `GET /api/scans/{id}` | Adds `jobs: [{scanner, status, started_at, completed_at, error, pages_crawled}]`. Top-level `pages_crawled` is the network job's value. |
| `GET /api/scans/{id}/services` | Each service adds `found_by` and `findings: [{scanner, auth_method, severity, evidence}]` |
| `GET /api/scans/{id}/services/{sid}/urls` | Each URL adds `scanner` and `sources`. Optional `?scanner=` filter. |
| `PATCH /api/scans/{id}/services/{sid}` | Unchanged. D4 decides whether `dns_failed` joins `unknown` and `no_response` as values a user can fill in. |
| `POST /api/scans/{id}/cancel` | Cancels queued jobs directly and flags running ones, then calls `finalize_scan` if every job has finished |
| `GET /api/apps/{id}/diff` | Unchanged; it keys on origin. `found_by` changes could be added later. |
| SSE | New event types (§5) |

The frontend has to handle `partial`, and should show `found_by` and each scanner's findings. Fields it doesn't know about break nothing.

## 7. Migration steps

Each step leaves `main` working and can be tested on its own. The existing Alembic history is replaced by one new initial revision (step 3).

### Step 0: Save a baseline (before any code changes)

The old databases are dropped in step 7, and steps 3 and 4 are checked against results from today's code.

- Pick a target you know well, ideally one both scanners cover.
- Run today's network-interceptor on it twice, so you know how much two crawls of the same target normally differ. Save `GET /api/scans/{id}`, `/services` and each service's `/urls` as JSON.
- Run today's config-tracer on the same target and save `GET /scans/{id}/services` and `/urls`.
- Don't commit the files, since they name internal hosts.

### Step 1: Bring the config engine in (no behavior change)

- Copy `config_tracer/` into this repo, minus `api/`, `db/` and `worker.py`. Trim `settings.py` down to `ScanSettings`.
- Add `aiohttp` to `requirements.txt`, pinned as in config-tracer.
- Move the engine tests (`test_config_tracer.py`, `test_pipeline.py`, `test_report.py`) and the fixture servers from their `conftest.py`. Drop `test_api.py` and `test_worker.py`.
- **Done when:** `pytest` passes, including the moved tests.

### Step 2: Combined vocabulary

- `core/enums.py`: add `login_redirect` and `dns_failed`, plus `Scanner` and `JobStatus`. `api/models.py`: add `partial` to `ScanStatus`.
- `core/translate.py`: extend `severity_for` to the new values.
- `core/merge.py`: the cross-scanner order and the refinements, with unit tests, including the `negotiate`/`kerberos` and `dns_failed`-with-IPs cases.
- **Done when:** the unit tests pass. No database change is needed.

### Step 3: Fresh database and the job queue (network only)

The new schema and the code that uses it land together, because today's worker reads `scans.worker_id` and `heartbeat_at`, which the new `scans` table doesn't have.

- Create two empty databases, `f35` and `f35_test`, and point `DATABASE_URL` in `.env` at the first.
- Delete `alembic/versions/*` and write one initial revision that creates the whole schema from §4.2, including the CHECK constraints from §4.1. As network-interceptor's current initial migration does, add the `use_alter` foreign keys (`apps.current_scan_id`, `services.evidence_url_id`, `service_findings.evidence_url_id`) explicitly, because `op.create_table` skips them on PostgreSQL.
- Update `core/db.py` to match: add `ScanJobRow` and `ServiceFindingRow`, and remove the worker columns from `ScanRow`.
- `core/jobs.py` replaces `worker/queue.py` and adds `finalize_scan`.
- `POST /api/scans` creates one network job. Cancel works on jobs.
- The network runner writes a finding and `urls.scanner`.
- Adopt config-tracer's test-database guard: the suite refuses to run unless the database name ends in `_test`.
- **Done when:**
  - `alembic upgrade head`, `downgrade base` and `upgrade head` again all run cleanly on the empty database.
  - `tests/integration` (`test_queue`, `test_patch_service`) passes after adapting, and `scripts/e2e.py` passes.
  - A scan of the step 0 target gives the same services as the baseline, allowing for the normal difference between two crawls.

Anyone else with a network-interceptor database, such as a teammate's machine or a shared dev environment, has to drop and recreate it, because the old revisions are gone.

### Step 4: Config worker

- Read `WORKER_SCANNER` in `worker/__main__.py`. Add the config runner and `translate.config_report_to_rows`, which applies `strip_url`, resolves `Location`, maps a missing status to 0, and converts verdicts with `AuthMethod(value)` (§4.1).
- `POST /api/scans` accepts `scanners: ["config"]`.
- **Done when:**
  - A config-only scan against config-tracer's fixture servers produces the services that config-tracer's own tests expect.
  - A config-only scan of the step 0 target matches the config-tracer baseline, apart from URLs that now have their query strings removed.

### Step 5: Both scanners by default

- `POST /api/scans` defaults to both scanners. Turn on merging, `partial`, and the API fields from §6.
- **Done when:** an integration test runs both runners with stubbed engines (as config-tracer's worker tests do) and checks the merge, `partial`, submit refused on a partial scan, cancel mid-run, and a reaped job finalizing its scan.

### Step 6: Frontend

- Show the `partial` state, job progress, `found_by`, each scanner's findings, and the new URL fields `scanner` and `sources`.

### Step 7: Retire config-tracer and the old databases

- Stop config-tracer's API and worker, and remove the project.
- Drop `config_tracer_api`, `network-interceptor` and `network-interceptor-test`, plus `config_tracer_api_test` if you created one.
- Delete the step 0 baseline files.

## 8. Open decisions

Already decided: the merged service starts on a fresh database, and neither project's data is carried over (2026-09-30).

| # | Question | Recommendation |
|---|---|---|
| D1 | Should the config crawl reuse the network scanner's login session (`storage_state`)? Without it, on an app behind SSO, config-tracer sees only the login page's bundles. The probes stay anonymous either way. | Yes, after step 5: add a `storage_state` option to `config_tracer.crawl`. |
| D2 | What exposure state does an app get when its latest scan is `partial`? | `failed`, meaning rerun. No new state. |
| D3 | Retry a job whose worker died? | Not in the first version. The `attempts` column is ready. |
| D4 | Can a user fill in the auth method of a `dns_failed` service? | Yes, for the same reason `unknown` and `no_response` allow it. |
| D5 | Is the cross-scanner order in §4.3 right? In particular, config's `no_response` outranks network's `unauthenticated`. | Yes. Review it against real scans during step 5. |
| D6 | Should network jobs get a hard timeout? | Yes, with the same setting the config runner uses. |
