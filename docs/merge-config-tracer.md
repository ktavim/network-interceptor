# Merging config-tracer into network-interceptor

**Status:** done, 2026-10-02. Proposed 2026-09-30, revised 2026-10-01. Steps 1 to 3 (§7) were done 2026-10-01, and steps 4 to 6, 2026-10-02. The first of D2's two follow-ups, the requeue on a graceful worker shutdown, was done 2026-10-02 as well; the second is open. The merged service runs on a fresh database, `f35`; the step 3 comparison scan there is `cd26d91452d74820ac5edb6f78cdd5c6`, the step 4 one is `f57ef053196e4eb1b3859592f5c72b8e` and the step 5 one is `41375e3065e7470f92c862f9935da605`. Both existing databases hold only dev data; they stay in place, untouched, as the record of what today's code produced.

## 1. Goal

One request (`POST /api/scans`) runs both scanners on the same target. Results land in one database and come back as one list of services per origin, with each scanner's evidence kept.

Out of scope for this plan:

- Carrying over existing data. Both databases hold only dev data, so the merged service starts on a fresh database (§7, step 3). The old databases are kept, not migrated.
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
     worker, WORKER_SCANNER=interceptor                              worker, WORKER_SCANNER=tracer
     claims scanner='interceptor' jobs                               claims scanner='tracer' jobs
     runs crawler.Mapper                                             runs config_tracer.pipeline.run_scan
                  └──────────────► urls, service_findings, services ◄─────────────┘
                                   (the last job to finish sets the scan's final status)
```

- One repo (network-interceptor), one new database, one API.
- Postgres stays the queue. The API never calls a worker; it inserts job rows.
- config-tracer's engine (crawl, extract, resolve, probe, report) moves in as a library. Its API, database layer, worker and migrations are retired.
- Both workers use the same image and entry point. `WORKER_SCANNER` picks which jobs a worker claims, so the two can be scaled independently.
- Naming: `network-interceptor` and `config-tracer` are today's two projects, and the repo keeps the first name. `interceptor` and `tracer` are the two scanners inside the merged service.

Repo layout after the merge:

```
api/            existing routes, extended (§6)
core/
  db.py         + ScanJobRow, ServiceFindingRow
  enums.py      combined AuthMethod; new Scanner and JobStatus
  jobs.py       NEW: claim, heartbeat, reap and finish on scan_jobs, plus finalize_scan (replaces worker/queue.py)
  merge.py      NEW: combines the scanners' findings into one service verdict
  translate.py  + tracer_report_to_rows
crawler/        interceptor engine, unchanged
config_tracer/  tracer engine, moved in (everything outside api/, db/ and worker.py)
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
| `unknown` | tracer (interceptor: in theory only) | review | tracer: a bare 401, a coarse 4xx (400, 403, 404, 407), a 5xx, or a redirect that isn't to a login or an IdP. interceptor: a tag outside the vocabulary, which no producer emits (`test_rank_table_has_no_tags_the_crawler_cannot_emit`), so in practice every `unknown` the merge sees is the tracer's. |
| `no_response` | both | review | |
| `dns_failed` | tracer | review | **New.** The interceptor reports a DNS failure as `no_response` with `failure_reason = net::ERR_NAME_NOT_RESOLVED`. |
| `kerberos` | interceptor | cleared | |
| `bearer` | both | cleared | |
| `oauth` | both | cleared | |
| `login_redirect` | tracer | cleared | **New.** |
| `api_key` | interceptor | cleared | |
| `unauthenticated` | both | cleared | |

This has to come first. `tag_to_auth_method` maps any value it doesn't know to `unknown`, so without it every `login_redirect` and `dns_failed` from the tracer would silently become `unknown` with severity review.

Because the schema starts fresh, every column that holds one of these vocabularies gets a CHECK constraint listing its values: the auth method, severity, scanner and status columns. This is what config-tracer does today (`native_enum=False, create_constraint=True`). Adding a value then takes a one-line migration.

The constraint only catches values that skip `tag_to_auth_method`, because that function turns any unrecognized tag into `unknown` before it reaches the database. That fallback stays in the interceptor path, where it's deliberate. The tracer path must convert with `AuthMethod(value)`, which raises on an unknown value, and never go through `tag_to_auth_method`. A value missing from the combined vocabulary then fails loudly instead of becoming `unknown`.

New enums: `Scanner` (`interceptor`, `tracer`) and `JobStatus` (`queued`, `running`, `completed`, `failed`, `cancelled`). `ScanStatus` gains `partial`.

### 4.2 Tables

`apps`, `submissions` and `scan_events` are unchanged.

#### `scans` (changed): the parent scan, one per request

| Column | Notes |
|---|---|
| `id`, `app_id`, `name`, `url`, `started_by`, `started_at`, `completed_at`, `error`, `cancel_requested_at` | As in network-interceptor today |
| `status` | Derived from the scan's jobs (§4.4). Adds `partial`. |

Compared with today's table, `worker_id`, `heartbeat_at` and `pages_crawled` move to `scan_jobs`, and `max_depth` moves into the interceptor job's `settings`.

`cancel_requested_at` stays on `scans` because a cancel applies to the whole scan. Each job's heartbeat reads it.

#### `scan_jobs` (new): one per scanner per scan; this is the queue

| Column | Type | Notes |
|---|---|---|
| `id` | String PK | Hex UUID, like the other IDs |
| `scan_id` | FK `scans`, `ON DELETE CASCADE` | |
| `scanner` | String, CHECK in (`interceptor`, `tracer`) | |
| `status` | String | `JobStatus` |
| `settings` | JSONB, NOT NULL | Snapshot taken at request time. Never holds credentials. |
| `attempts` | Integer, default 0 | |
| `worker_id`, `heartbeat_at` | | Moved from `scans` |
| `error` | Text | |
| `created_at`, `started_at`, `completed_at` | timestamptz | |
| `pages_crawled` | Integer, nullable | |

Constraints: `UNIQUE (scan_id, scanner)`, and an index on `(scanner, status, created_at)` for the claim query.

Settings snapshots:

- **interceptor:** `{"max_depth": …}` in the first version. The worker still merges it onto `config.json`, as it does today.
- **tracer:** `ScanSettings` built from the API's environment and dumped to JSON, as config-tracer does today.

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
| `sources` | **New**, TEXT[], default `'{}'`. Filled only by the tracer, with its provenance strings (`network:`, `js:`, `dom:`, `redirect:`, `synthesized:`). |
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
| `redirect_url` | `location` of a 3xx, resolved against `url`, then passed through `strip_url`; NULL for any other status | network-interceptor stores it resolved and stripped, and only for a redirect. config-tracer stores it raw, and it's often relative. |
| `resource_type` | `'probe'` | Lets the UI tell a probe apart from a captured request |
| `page_url` | `''` | The provenance is in `sources` |
| `sent_auth_scheme` | NULL | The probes are anonymous |
| `sources` | `sources`, with the URL after `network:`, `js:`, `redirect:` and `synthesized:` passed through `strip_url` | Those four name a URL, and `redirect:` and `synthesized:` repeat a probed one, so they can carry the query string that `url` just lost. `dom:` names a page element and is kept as is. |

### 4.3 Merge rules

Each scanner keeps its own per-origin rule. The two orderings disagree in two places, on purpose:

| Value | interceptor (`_AUTH_RANK`) | tracer (`_VERDICT_PRECEDENCE`) |
|---|---|---|
| `no_response` | Lowest: any answer beats no answer. Requests the browser aborted (`net::ERR_ABORTED`) are common noise. | Above `unauthenticated`: a probe that timed out is a URL nobody saw, and an open sibling must not hide it. |
| `unknown` | Above every cleared scheme. Moot in practice: the interceptor never emits it (§4.1). | Below `bearer`, `oauth` and `login_redirect`: a concrete scheme on the host beats a 404 or a bare 401. |

Each choice is right for the scanner that makes it, so neither ordering changes. The merge only combines the two scanners' findings for an origin.

To compute a service's combined verdict:

1. **One finding:** that finding is the verdict.
2. **Two findings:** apply these refinements first.
   - If one finding is `negotiate` and the other is `kerberos` or `ntlm`, drop the `negotiate`. It's the same SPNEGO challenge; the interceptor saw which mechanism was used, and the anonymous probe can't.
   - If the tracer says `dns_failed` but the interceptor finding has IPs, drop the `dns_failed`. The lookup worked for the other scanner.
   - If the interceptor says `no_response` and the tracer says anything but `no_response` or `dns_failed`, drop the interceptor finding. The interceptor's per-origin `no_response` means every browser request to the origin failed, usually `net::ERR_ABORTED` from a cancelled navigation or a prefetch, and the tracer's answer shows the origin is reachable.
   - Then take the finding that ranks higher in the order below. On a tie, take the interceptor finding, since observed traffic beats a probe.
3. Set `severity = severity_for(verdict)`, and set `evidence_url_id` to the winning finding's evidence.

Cross-scanner order, highest first:

`ntlm` > `basic` > `other` > `negotiate` > `kerberos` > `bearer` > `oauth` > `login_redirect` > `api_key` > `unknown` > `no_response` > `dns_failed` > `unauthenticated`

Why this order (D4):

- A blocker always wins, and `negotiate` stays above every cleared scheme, because a SPNEGO challenge may be NTLM underneath.
- A concrete scheme beats a non-answer (`unknown`, `no_response`, `dns_failed`). Both scanners' own rules say so: the tracer collapses `{bearer, unknown}` to `bearer`, and the interceptor ranks `no_response` below everything. After the refinements, every non-answer that reaches this comparison is the tracer's, and the tracer's `unknown` is a 404, a bare 401 or a 5xx (§4.1), which can't hide NTLM or Basic: those schemes announce themselves in the challenge, and the tracer classifies them from it. The order the plan first had, with the non-answers above the cleared schemes, would have put every app with a token API on `unknown`/review: the tracer HEADs the API base named in the config and gets a 404 or a bare 401, while the interceptor watched the browser use a bearer token.
- A non-answer beats `unauthenticated`, as the tracer's rule says: a probed URL that answered nothing recognizable must not be hidden by open siblings. The cost is a review the reviewer can clear in seconds from `findings` (§6).

So the combined severity can be lower than one finding's, in exactly one case: a non-answer from one scanner meets a concrete cleared scheme from the other. The finding stays visible under `findings`.

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
- `derive_exposure_state` treats `partial` like `failed` (D1).

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

- **interceptor:** today's `run_scan_job`. It writes a finding plus `urls` rows with `scanner='interceptor'`, instead of whole services.
- **tracer:** `config_tracer.pipeline.run_scan([scans.url], ScanSettings(**job.settings))`, then `translate.tracer_report_to_rows`, then the same write path. It emits `auth_detected` per service, as the interceptor does.

Both runners run their engine inside `asyncio.timeout(SCAN_TIMEOUT_S)` (D5). On expiry the job is `failed` with `TimeoutError: scan exceeded SCAN_TIMEOUT_S=…`, the engine's cleanup still runs, and the scan ends `partial` if the other job completed. `SCAN_TIMEOUT_S` comes from the worker process's environment, so each deployment sets its own, which is one value per scanner. The tracer keeps config-tracer's 900 s. The interceptor's default is 3600 s, a bit over four times the longer step 0 baseline crawl (13:54), because a depth-3 crawl with 20 clicks per page legitimately runs far longer than the tracer's one-page crawl. The lease needs no `stale > timeout` rule like config-tracer's: staleness here is heartbeat based and doesn't depend on how long a job runs.

Retries (D2): a job interrupted by a graceful worker shutdown goes back to the queue and is run again from the start, as config-tracer did. A job whose worker stops heartbeating is failed by the reaper, with no retry. `claim_next` increments `attempts`, so the column counts every run of a job. The first version had no requeue either: until D2's first follow-up, 2026-10-02, a shutdown failed the job with `worker shut down`.

Events:

| Event | When | Payload |
|---|---|---|
| `scan_started` | Unchanged | Unchanged |
| `job_started` | A worker claims a job | `{scanner}` |
| `auth_detected` | Unchanged | Adds `scanner` |
| `job_completed` / `job_failed` | A job ends | `{scanner, services}` or `{scanner, error}` |
| `job_requeued` | A worker shutting down puts its running job back in the queue (D2); the job's next `job_started` follows when a worker claims it again | `{scanner}` |
| `blocker_found` | Moves to `finalize_scan`; emitted once per combined blocker | Unchanged |
| `scan_completed` | The last job ends and the status is `completed` or `partial` | Adds `{partial, failed_scanners}` |
| `scan_failed` | The status is `failed` or `cancelled` | Unchanged |

The terminal events are still `scan_completed` and `scan_failed`, so `TERMINAL_EVENTS` and the SSE streams keep working. A partial scan ends its stream with `scan_completed` and `partial: true`.

## 6. API changes

Everything is additive except the new status value.

| Endpoint | Change |
|---|---|
| `POST /api/scans` | Request and response unchanged. Always creates one `scan_jobs` row per scanner. |
| `GET /api/scans`, `GET /api/apps/{id}/scans` | `status` can be `partial` |
| `GET /api/scans/{id}` | Adds `jobs: [{scanner, status, started_at, completed_at, error, pages_crawled}]`. Top-level `pages_crawled` is the interceptor job's value. |
| `GET /api/scans/{id}/services` | Each service adds `found_by` and `findings: [{scanner, auth_method, severity, evidence}]` |
| `GET /api/scans/{id}/services/{sid}/urls` | Each URL adds `scanner` and `sources`. Optional `?scanner=` filter. |
| `PATCH /api/scans/{id}/services/{sid}` | `dns_failed` joins `unknown` and `no_response` as values a user can fill in, and as values nobody can set (D3). Otherwise unchanged. |
| `POST /api/scans/{id}/cancel` | Cancels queued jobs directly and flags running ones, then calls `finalize_scan` if every job has finished |
| `GET /api/apps/{id}/diff` | Unchanged; it keys on origin. `found_by` changes could be added later. |
| SSE | New event types (§5) |

## 7. Migration steps

Each step leaves `main` working and can be tested on its own. The existing Alembic history is replaced by one new initial revision (step 3).

### Step 0: Baseline (recorded before any code changes)

Steps 3 and 4 are checked against results from today's code. Those results live in the old databases, which stay in place, so the baseline is a set of scan IDs.

Recorded 2026-10-01, with code at `da05d49` (network-interceptor) and `fa2da7d` (config-tracer):

- Target: `https://practicesoftwaretesting.com`, which both scanners cover.
- Today's network-interceptor ran on it twice, to show how much two crawls of the same target normally differ. The longer duration sets the interceptor's `SCAN_TIMEOUT_S` default (D5).
- Today's config-tracer ran on it once.

| Scanner | Scan ID | Settings | Duration | Pages | Services | URLs |
|---|---|---|---|---|---|---|
| interceptor | `b0d3bb9ce9d343d7999331c5dcffaaf1` | `max_depth` omitted (3 from `config.json`) | 13:54 | 7 | 19 | 531 |
| interceptor | `54893a4211d846edbb731f281ac8f50d` | same | 8:35 | 6 | 18 | 459 |
| tracer | `b65cef5d-dffe-46f4-8a5a-d13415f7bf7b` | `max_pages=1`, `follow_links=false` | 0:39 | | 14 | 44 |

- Normal difference between the two crawls: 18 origins in common, all with the same verdict. One origin (`www.google.com`, one request) is in the first crawl only. Request counts differ on three origins (`api.practicesoftwaretesting.com`, `unsplash.com`, `www.google-analytics.com`).
- Neither crawl was logged in, so every interceptor service is `unauthenticated`. On this target the step 5 check sees only one cross-scanner rule, a non-answer beating `unauthenticated`; the other rules rest on the step 2 unit tests.
- The step 3 comparison scan must also omit `max_depth`.
- After step 3, today's network-interceptor API no longer runs, so the comparisons in steps 3 and 4 read the old `services` and `urls` tables directly.

### Step 1: Bring the tracer engine in (no behavior change)

- Copy `config_tracer/` into this repo, minus `api/`, `db/` and `worker.py`. Trim `settings.py` down to `ScanSettings`.
- Add `aiohttp` to `requirements.txt`, pinned as in config-tracer.
- Move the engine tests (`test_config_tracer.py`, `test_pipeline.py`, `test_report.py`) and the fixture servers from their `conftest.py`. Drop `test_api.py` and `test_worker.py`.
- **Done when:** `pytest` passes, including the moved tests.

### Step 2: Combined vocabulary

- `core/enums.py`: add `login_redirect` and `dns_failed`, plus `Scanner` and `JobStatus`. `api/models.py`: add `partial` to `ScanStatus`.
- `core/translate.py`: extend `severity_for` to the new values.
- `core/merge.py`: the cross-scanner order and the refinements, with unit tests, including the `negotiate`/`kerberos`, `dns_failed`-with-IPs and interceptor-`no_response`-with-tracer-answer cases, and the token-API case (`bearer` + `unknown` → `bearer`).
- `api/routes_scans.py`: `dns_failed` joins `_FILL_IN_AUTH_METHODS` (D3). It lands here because the PATCH body is typed `AuthMethod`: once the enum has `dns_failed`, a user could otherwise set a service to it.
- **Done when:** the unit tests pass. No database change is needed.

### Step 3: Fresh database and the job queue (interceptor only)

The new schema and the code that uses it land together, because today's worker reads `scans.worker_id` and `heartbeat_at`, which the new `scans` table doesn't have.

- Create two empty databases, `f35` and `f35_test`, and point `DATABASE_URL` in `.env` at the first.
- Delete `alembic/versions/*` and write one initial revision that creates the whole schema from §4.2, including the CHECK constraints from §4.1. As network-interceptor's current initial migration does, add the `use_alter` foreign keys (`apps.current_scan_id`, `services.evidence_url_id`) explicitly, because `op.create_table` skips them on PostgreSQL. `service_findings.evidence_url_id` is in no cycle, so it needs no `use_alter` and goes inline.
- Update `core/db.py` to match: add `ScanJobRow` and `ServiceFindingRow`, and remove the worker columns from `ScanRow`.
- `core/jobs.py` replaces `worker/queue.py` and adds `finalize_scan`.
- `POST /api/scans` creates one interceptor job. Cancel works on jobs.
- The interceptor runner writes a finding and `urls.scanner`.
- Adopt config-tracer's test-database guard: the suite refuses to run unless the database name ends in `_test`.
- **Done when:**
  - `alembic upgrade head`, `downgrade base` and `upgrade head` again all run cleanly on the empty database.
  - `tests/integration` (`test_queue`, `test_patch_service`) passes after adapting, and `scripts/e2e.py` passes.
  - A scan of the step 0 target gives the same services as the baseline scans in the old `network-interceptor` database, allowing for the normal difference between two crawls.

Anyone else running network-interceptor, such as a teammate's machine or a shared dev environment, has to create their own `f35` database and repoint `DATABASE_URL`. Their old database can stay. The new code fails loudly if it's pointed at one: Alembic stops on a revision it doesn't know, and the app can't find `scan_jobs`.

### Step 4: Tracer worker

- Read `WORKER_SCANNER` in `worker/__main__.py`. Add the tracer runner and `translate.tracer_report_to_rows`, which applies `strip_url`, resolves `Location`, maps a missing status to 0, and converts verdicts with `AuthMethod(value)` (§4.1).
- Add the `SCAN_TIMEOUT_S` wrapper to both runners (§5, D5), with a unit test that stubs an engine that never returns.
- `POST /api/scans` creates both jobs.
- **Done when**, with only a tracer worker running (`WORKER_SCANNER=tracer`), so the interceptor job stays queued and the scan's services come from the tracer alone:
  - A scan against config-tracer's fixture servers produces the services that config-tracer's own tests expect.
  - A scan of the step 0 target matches the baseline scan in the old `config_tracer_api` database, apart from URLs that now have their query strings removed.

Recorded 2026-10-02:

- `WORKER_SCANNER` is required. A worker started without it, or with any value but `interceptor` or `tracer`, exits with a message; it doesn't default to one scanner.
- From this step a scan ends only when a worker of each scanner has run its job. `scripts/e2e.py` starts both kinds.
- The fixture-server check is `tests/integration/test_tracer_scan.py`.
- The step 0 target check is scan `f57ef053196e4eb1b3859592f5c72b8e`: 14 services and 44 URLs, as in the baseline, with the same verdict, addresses and evidence URL for every service and the same method, status, verdict, challenge, redirect target and sources for every URL. Three baseline URLs are stored shorter, each having lost a fragment (`#…`), which `strip_url` drops along with the query string. The tracer job took 0:57.
- That scan was cancelled after the comparison, so its queued interceptor job never ran and its services stay the tracer's alone. Its status is `cancelled`.

### Step 5: Both scanners by default

- Run both workers. Turn on merging, `partial`, and the API fields from §6. `derive_exposure_state` adds `partial` to the statuses it maps to `failed` (D1).
- **Done when:**
  - An integration test runs both runners with stubbed engines (as config-tracer's worker tests do) and checks the merge, `partial`, submit refused on a partial scan, cancel mid-run, and a reaped job finalizing its scan.
  - On the step 0 target, every service whose combined verdict differs from the interceptor's finding has been read and makes sense (D4). This is the check of the cross-scanner order against real scans.

Recorded 2026-10-02:

- The merge and `partial` were already on: they came with `finalize_scan` in step 3 and have applied to two jobs since step 4. This step added the response fields of §6 (`jobs`, `found_by`, `findings`, `scanner`, `sources`, `?scanner=`) and the D1 line.
- One fix beyond the list: `GET /api/scans/{id}/events` did not count `partial` as an ended scan, so a client resuming past the terminal event of a partial scan was sent keepalives for ever.
- The services in a diff's `added` and `removed` carry `found_by` and `findings` too, as they are the same shape as a listed service.
- The integration test is `tests/integration/test_both_scanners.py`. `scripts/e2e.py` checks the new fields, and with `--slow` that a partial scan can't be submitted and leaves its app `failed`.
- The step 0 target check is scan `41375e3065e7470f92c862f9935da605`, with a worker of each scanner running: `completed` in 11:27 (the tracer job took 0:56), 7 pages, 26 services and 571 URLs.
  - 12 services are the interceptor's alone, 8 the tracer's alone, and both found 6. Each scanner's own findings are what it found alone: the interceptor's 18 are the origins and verdicts of the step 3 scan, the tracer's 14 those of the step 4 scan.
  - Of the 6 that both found, 4 agree (`unauthenticated`). The other 2 differ from the interceptor's finding, both by the one rule step 0 expected, a non-answer beating `unauthenticated`:
    - `api.practicesoftwaretesting.com`: `unauthenticated` from 48 browser requests, `unknown` from the tracer's HEAD of the API base a bundle names, which answered 404. Combined: `unknown`, review. It reads right for another reason too: two of the 48 requests (`GET /users/me`, `POST /favorites`) got a 401 that names no scheme. The API takes a token after login, and the crawl wasn't logged in.
    - `unsplash.com`: `unauthenticated` from 17 browser requests, all to the host's bot-challenge page and its static files. `unknown` from 20 probes of the photo-credit links in the products JSON: nine answered 200, ten redirected within the host (307, 308) and one answered 404. Combined: `unknown`, review. This is the cost D4 accepts, a review that `findings` settles.
  - The 8 the tracer found alone take its verdict (§4.3, one finding): 3 `unauthenticated`, and 5 `unknown` from a 404 or a redirect (`cloudflareinsights.com`, `popper.js.org`, `jwt.io`, and `www.w3.org` on ports 80 and 443). They are links and XML namespaces that the bundles name and no page calls.
  - So the interceptor alone has 18 services, all cleared, and the merged scan has 26: 19 cleared, 7 review, no blockers. Every review is a tracer `unknown`, and none argues for another order. What they show is how much review the tracer's `unknown` adds on a target with no blocker: it classes a 404, and any redirect that isn't to a login or an IdP, as `unknown`, which is its own detection logic and out of scope here (§1).

### Step 6: Retire config-tracer

- Stop config-tracer's API and worker, and remove the project.
- `config_tracer_api` and `network-interceptor` stay as they are. They're the only record of what today's code decided for each origin, they cost nothing, and the new code can't run against them (step 3). Drop them whenever nobody needs the comparison anymore.

Recorded 2026-10-02:

- There was nothing to stop: no config-tracer API or worker was running, and no service or scheduled task starts one.
- The project directory is deleted.

## 8. Decisions

None open. Decided:

- The merged service starts on a fresh database, and neither project's data is carried over (2026-09-30).
- The old databases are kept rather than dropped, so the baseline stays queryable (2026-10-01).
- **D1:** An app whose latest scan is `partial` gets exposure state `failed`, meaning rerun. No new state. A partial scan supports no other action, because submit and the manual auth fix both go through `_latest_completed_scan_id`, and `last_scan_status` carries `partial` so the frontend can still label the card. One line in `derive_exposure_state` (2026-10-01).
- **D2:** No retries in the first version, to keep the merge small. Two follow-ups, in this order, once step 5 is done. First, requeue on graceful shutdown: `_record_interrupted(SHUTDOWN)` calls `release` instead of `record_failure`; the job keeps its `created_at`, so it returns to the front of the queue, and `scans.status` stays `running`. Second, requeue from the reaper, which needs an attempt cap and a sweep that fails capped-out rows. Don't copy config-tracer's shape there: a shutdown requeue of a row at `attempts == max` leaves it `pending` forever, because claim filters `attempts < max` and `recover_stale` only touches `running` rows (2026-10-01).

  The first follow-up was done 2026-10-02. It differs from the sketch above in three ways:
  - `_record_interrupted(SHUTDOWN)` calls a new `requeue`, not `release`. `release` is for a job claimed during a shutdown that never started: it returns the scan to `queued` when no other job has started, and the next claim then resets `scans.started_at`. `requeue` leaves the scan row alone, which is what "stays `running`" needs.
  - If a cancel has been requested, `requeue` ends the job as `cancelled` instead. A cancel made after the worker's last heartbeat reaches the worker only as its own shutdown, and the cancel ended the scan's queued jobs when it was made, so nothing would end this one until a worker claimed it again. One gap is left, which `release` has had since step 3: a cancel whose transaction overlaps the requeue's can still miss the job. The worker that claims it next ends it at its first heartbeat, and so does a second cancel.
  - A new event, `job_requeued` (§5). After it the scanner's `job_started` comes a second time, and its second run repeats the `page_visited` and `auth_detected` events of the first, so a stream consumer needs the marker between them.

  There is no attempt cap yet, and this follow-up needs none: only a shutdown requeues, and a job can't cause one. A job that raises still fails, and a worker that dies still leaves its job to the reaper. The second follow-up, the requeue from the reaper, is open.
- **D3:** A user can fill in the auth method of a `dns_failed` service, and can't set a service to `dns_failed`. The rule behind `_FILL_IN_AUTH_METHODS` is that a manual value may replace only what the scanner couldn't tell, and `dns_failed` is that: the origin is named in a config or bundle and nobody resolved the host. Without the fill-in, the only resolution would be `excluded`, which is wrong for a host the owner knows is NTLM. `dns_failed` joins the tuple, the 409 message names it, and `test_patch_service` gets a case (2026-10-01).
- **D4:** The cross-scanner order is the one in §4.3, revised from the first draft: the non-answers (`unknown`, `no_response`, `dns_failed`) moved below the concrete cleared schemes and stay above `unauthenticated`. The first draft would have put every app with a token API on `unknown`/review. The tracer's `no_response` still outranks the interceptor's `unauthenticated`. A third refinement drops an interceptor `no_response` when the tracer got an answer. Step 5 checks the order against the step 0 target (2026-10-01).
- **D5:** Both runners get a hard timeout, `asyncio.timeout(SCAN_TIMEOUT_S)`, read from each worker process's environment, so one value per scanner. Same mechanism, not the same value: the tracer's 900 s was sized for a one-page crawl, and a depth-3 interceptor crawl runs far longer legitimately. The interceptor's default is 3600 s, a bit over four times the longer step 0 baseline crawl (13:54; the other took 8:35). Without it a hung crawl holds a slot and keeps its scan `running` until someone cancels; with `CRAWLER_MAX_PARALLEL=2`, two of those stall the queue. No `stale > timeout` rule is needed, because the lease is heartbeat based (2026-10-01).
