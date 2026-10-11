"""End-to-end smoke test: the real API, workers of both scanners and Chromium against a local test site.

    TEST_DATABASE_URL=postgresql+asyncpg://... python scripts/e2e.py [--slow]

It migrates and truncates that database, so its name must end in `_test`. --slow adds the
hard-kill scenario (~75s more).
"""
import argparse
import asyncio
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import aiohttp
import asyncpg
from aiohttp import web
from sqlalchemy.engine import make_url

REPO = Path(__file__).resolve().parent.parent
WINDOWS = sys.platform == "win32"
API = "http://127.0.0.1:8811"
SITE = "http://127.0.0.1:8801"
TERMINAL = ("scan_completed", "scan_failed")
ENDED = {"completed", "partial", "failed", "cancelled"}

results = []


def check(name, ok, detail=""):
    results.append((name, bool(ok)))
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}" + (f" -- {detail}" if detail else ""), flush=True)


# ---------------------------------------------------------------- test site

# The browser calls 8802 and 8803, which is what the interceptor sees. The config names 8803
# again and 8804, which no page calls: only the tracer, reading the config, finds that one.
EXTERNALS = (
    '<img src="http://127.0.0.1:8802/p.png">'
    '<script>fetch("http://127.0.0.1:8803/api").catch(() => {})</script>'
    '<script>window.__CONFIG__ = {"api": "http://127.0.0.1:8803/api", "docs": "http://127.0.0.1:8804/docs"};</script>'
)


def _page(body):
    return web.Response(text=f"<html><body>{EXTERNALS}{body}</body></html>", content_type="text/html")


async def _fast(_):
    return _page("<p>fast</p>")


async def _slow(_):
    buttons = "".join(f'<button type="button">b{i}</button>' for i in range(10))
    links = "".join(f'<a href="/slow/{i}">sub {i}</a>' for i in range(3))
    return _page(buttons + links)


async def _slow_sub(req):
    buttons = "".join(f'<button type="button">s{i}</button>' for i in range(5))
    return _page(f"<p>sub {req.match_info['n']}</p>{buttons}")


async def _pixel(_):
    return web.Response(body=b"\x89PNG\r\n\x1a\n" + b"\x00" * 16, content_type="image/png")


async def _basic_api(_):
    # CORS header, or Chrome fails the cross-origin fetch before the crawler sees the 401.
    return web.Response(status=401, headers={"WWW-Authenticate": 'Basic realm="t"', "Access-Control-Allow-Origin": "*"})


async def _docs(_):
    return web.Response(text="docs")


async def start_site():
    runners = []
    for port, routes in (
        (8801, [web.get("/fast", _fast), web.get("/slow", _slow), web.get("/slow/{n}", _slow_sub)]),
        (8802, [web.get("/p.png", _pixel)]),
        (8803, [web.get("/api", _basic_api)]),
        (8804, [web.get("/docs", _docs)]),
    ):
        app = web.Application()
        app.add_routes(routes)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", port).start()
        runners.append(runner)
    return runners


# ---------------------------------------------------------------- processes

def send_ctrl_c(pid):
    """Runs as its own process: a real Ctrl+C to every process on pid's console, as a terminal would."""
    import ctypes

    kernel32 = ctypes.windll.kernel32
    kernel32.FreeConsole()
    if not kernel32.AttachConsole(pid):
        sys.exit(f"AttachConsole({pid}) failed: {kernel32.GetLastError()}")
    kernel32.SetConsoleCtrlHandler(None, True)  # ignore it ourselves
    if not kernel32.GenerateConsoleCtrlEvent(0, 0):  # CTRL_C_EVENT
        sys.exit(f"GenerateConsoleCtrlEvent failed: {kernel32.GetLastError()}")


def headless_shells():
    """Running headless Chromium processes, or None where they can't be counted."""
    if WINDOWS:
        out = subprocess.run(
            ["tasklist", "/FI", "IMAGENAME eq chrome-headless-shell.exe", "/FO", "CSV", "/NH"],
            capture_output=True, text=True,
        ).stdout
        return out.count("chrome-headless-shell")
    try:
        out = subprocess.run(["pgrep", "-f", "chrome-headless-shell"], capture_output=True, text=True).stdout
    except FileNotFoundError:
        return None
    return len(out.split())


def ports_in_use():
    busy = []
    for port in (8801, 8802, 8803, 8804, 8811):
        with socket.socket() as s:
            if not WINDOWS:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # ignore TIME_WAIT, not listeners
            try:
                s.bind(("127.0.0.1", port))
            except OSError:
                busy.append(port)
    return busy


def kill_tree(proc):
    """Kill a process and all it started: uvicorn's --workers children outlive a plain kill of their parent."""
    if proc.poll() is None:
        if WINDOWS:
            subprocess.run(["taskkill", "/F", "/T", "/PID", str(proc.pid)], capture_output=True)
        else:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    proc.wait()


async def wait_exit(proc, timeout):
    deadline = time.monotonic() + timeout
    while proc.poll() is None and time.monotonic() < deadline:
        await asyncio.sleep(0.2)
    return proc.poll()


class Harness:
    def __init__(self, sa_url, logs):
        self.sa_url = sa_url
        self.pg_dsn = make_url(sa_url).set(drivername="postgresql").render_as_string(hide_password=False)
        self.logs = logs
        self.api = None
        self.workers = {}

    def env(self, **extra):
        env = dict(os.environ, DATABASE_URL=self.sa_url, CRAWLER_CONFIG_PATH="__no_config__.json", PYTHONUNBUFFERED="1")
        env.update({k: str(v) for k, v in extra.items()})
        return env

    def _log(self, name):
        return open(self.logs / f"{name}.log", "ab")

    async def prepare_database(self):
        r = subprocess.run([sys.executable, "-m", "alembic", "upgrade", "head"],
                           env=self.env(), cwd=REPO, capture_output=True, text=True)
        if r.returncode:
            sys.exit(f"alembic upgrade head failed:\n{r.stdout}{r.stderr}")
        conn = await asyncpg.connect(self.pg_dsn)
        try:
            # Every other table hangs off apps, except the published-origins registry.
            await conn.execute("TRUNCATE apps, published_origins CASCADE")
        finally:
            await conn.close()

    def stop_api(self):
        if self.api is not None:
            kill_tree(self.api)
            self.api = None

    async def start_api(self, http, workers=1):
        self.stop_api()
        self.api = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "api.main:app", "--host", "127.0.0.1", "--port", "8811",
             "--workers", str(workers)],
            env=self.env(), cwd=REPO, stdout=self._log(f"api_w{workers}"), stderr=subprocess.STDOUT,
            start_new_session=not WINDOWS,
        )
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            try:
                async with http.get(f"{API}/health") as r:
                    if r.status == 200:
                        return
            except aiohttp.ClientError:
                pass
            await asyncio.sleep(0.3)
        raise RuntimeError("the API did not come up")

    def start_worker(self, name, max_parallel, scanner="interceptor"):
        kwargs = dict(start_new_session=True)
        if WINDOWS:
            # Its own hidden console, so a Ctrl+C can reach it the way a terminal's would.
            si = subprocess.STARTUPINFO()
            si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            si.wShowWindow = subprocess.SW_HIDE
            kwargs = dict(creationflags=subprocess.CREATE_NEW_CONSOLE, startupinfo=si)
        proc = subprocess.Popen(
            [sys.executable, "-m", "worker"],
            env=self.env(WORKER_SCANNER=scanner, CRAWLER_MAX_PARALLEL=max_parallel), cwd=REPO,
            stdout=self._log(f"worker_{name}"), stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, **kwargs,
        )
        self.workers[name] = proc
        return proc

    def worker_log(self, name):
        return (self.logs / f"worker_{name}.log").read_text(errors="replace")

    def stop_worker_gracefully(self, name):
        """Ctrl+C on Windows; SIGTERM elsewhere, which is what OpenShift sends. (ok, detail)"""
        proc = self.workers[name]
        if not WINDOWS:
            proc.send_signal(signal.SIGTERM)
            return True, "SIGTERM"
        r = subprocess.run([sys.executable, __file__, "--send-ctrl-c", str(proc.pid)],
                           creationflags=subprocess.CREATE_NO_WINDOW, capture_output=True, text=True)
        return r.returncode == 0, f"Ctrl+C {(r.stdout + r.stderr).strip()}".strip()

    def kill_all(self):
        self.stop_api()
        for proc in self.workers.values():
            kill_tree(proc)

    async def scan(self, scan_id):
        """The scan's status and error, and the worker that claimed its interceptor job."""
        conn = await asyncpg.connect(self.pg_dsn)
        try:
            return await conn.fetchrow(
                "SELECT s.status, s.error, j.worker_id FROM scans s "
                "LEFT JOIN scan_jobs j ON j.scan_id = s.id AND j.scanner = 'interceptor' WHERE s.id=$1",
                scan_id,
            )
        finally:
            await conn.close()

    async def jobs(self, scan_id):
        """{scanner: (status, error)} for the scan's jobs."""
        conn = await asyncpg.connect(self.pg_dsn)
        try:
            rows = await conn.fetch("SELECT scanner, status, error FROM scan_jobs WHERE scan_id=$1", scan_id)
            return {r["scanner"]: (r["status"], r["error"]) for r in rows}
        finally:
            await conn.close()

    async def events(self, scan_id):
        conn = await asyncpg.connect(self.pg_dsn)
        try:
            rows = await conn.fetch("SELECT seq, type, payload FROM scan_events WHERE scan_id=$1 ORDER BY seq", scan_id)
            return [(r["seq"], r["type"], json.loads(r["payload"])) for r in rows]
        finally:
            await conn.close()

    async def wait_status(self, scan_id, statuses, timeout):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            row = await self.scan(scan_id)
            if row["status"] in statuses:
                return row
            await asyncio.sleep(0.25)
        return await self.scan(scan_id)

    async def wait_running(self, scan_id):
        """Until the interceptor worker has claimed the scan's job and visited its first page."""
        await self.wait_status(scan_id, {"running"}, 15)
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if any(t == "page_visited" for _, t, _ in await self.events(scan_id)):
                return await self.scan(scan_id)
            await asyncio.sleep(0.25)
        return await self.scan(scan_id)

    async def wait_job_claimed(self, scan_id, scanner, timeout=15):
        """Until that scanner's worker has claimed the scan's job. Returns the job's status."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if (await self.jobs(scan_id))[scanner][0] != "queued":
                break
            await asyncio.sleep(0.25)
        return (await self.jobs(scan_id))[scanner][0]


async def check_no_chromium_left(name, baseline):
    await asyncio.sleep(3)
    now = headless_shells()
    if now is None or baseline is None:
        print(f"  [SKIP] {name} -- can't count Chromium processes here", flush=True)
    else:
        check(name, now == baseline, f"{now} running, {baseline} before")


# ---------------------------------------------------------------- API client

async def create_app(http, path):
    body = {"name": f"e2e {path}", "url": SITE + path, "owner_ad_group": "e2e"}
    async with http.post(f"{API}/api/apps", json=body) as r:
        assert r.status == 201, await r.text()
        return (await r.json())["id"]


async def create_scan(http, app_id):
    async with http.post(f"{API}/api/scans", json={"app_id": app_id}) as r:
        assert r.status == 200, await r.text()
        return (await r.json())["scan_id"]


async def cancel(http, scan_id):
    async with http.post(f"{API}/api/scans/{scan_id}/cancel") as r:
        return r.status


async def read_sse(http, url, last_id=None, max_events=None, timeout=120.0):
    """Events until a terminal one, max_events or timeout. Returns (events, how it ended)."""
    headers = {"Accept": "text/event-stream"}
    if last_id is not None:
        headers["Last-Event-ID"] = str(last_id)
    events, data = [], None
    try:
        async with asyncio.timeout(timeout):
            async with http.get(url, headers=headers, timeout=aiohttp.ClientTimeout(total=None)) as r:
                async for raw in r.content:
                    line = raw.decode().rstrip("\r\n")
                    if line.startswith("data:"):
                        data = line[5:].strip()
                    elif line == "" and data is not None:
                        events.append(json.loads(data))
                        data = None
                        if events[-1]["type"] in TERMINAL:
                            return events, "terminal"
                        if max_events and len(events) >= max_events:
                            return events, "max"
        return events, "closed"
    except TimeoutError:
        return events, "timeout"


def seqs(events):
    return [int(e["seq"]) for e in events]


# ---------------------------------------------------------------- scenarios

async def happy_path(h, http, fast_app):
    print("happy path", flush=True)
    notifications = asyncio.create_task(read_sse(http, f"{API}/api/notifications", timeout=90))
    await asyncio.sleep(0.5)
    scan_id = await create_scan(http, fast_app)
    events, ended = await read_sse(http, f"{API}/api/scans/{scan_id}/events", timeout=90)
    types = [e["type"] for e in events]
    check("stream runs scan_started .. scan_completed, seqs contiguous",
          ended == "terminal" and types[0] == "scan_started" and types[-1] == "scan_completed"
          and seqs(events) == list(range(len(events))), f"{ended} {types}")
    check("worker events reach the API", {"page_visited", "blocker_found"} <= set(types))
    row = await h.scan(scan_id)
    check("scan completed by a worker", row["status"] == "completed" and row["worker_id"], f"{row['status']} {row['worker_id']}")
    completed = sorted(e["payload"]["scanner"] for e in events if e["type"] == "job_completed")
    check("a worker of each scanner completed its job", completed == ["interceptor", "tracer"], str(completed))
    async with http.get(f"{API}/api/scans/{scan_id}") as r:
        jobs = {j["scanner"]: j["status"] for j in (await r.json())["jobs"]}
    check("the scan lists both jobs, completed", jobs == {"interceptor": "completed", "tracer": "completed"}, str(jobs))
    async with http.get(f"{API}/api/scans/{scan_id}/services") as r:
        listed = await r.json()
    services = {(s["host"], s["port"]): (s["auth_method"], s["severity"]) for s in listed}
    check("services: Basic on 8803 blocks, 8802 clears",
          services.get(("127.0.0.1", 8803)) == ("basic", "blocker")
          and services.get(("127.0.0.1", 8802), ("", ""))[1] == "cleared", str(services))
    check("the tracer adds 8804, which only the config names",
          services.get(("127.0.0.1", 8804)) == ("unauthenticated", "cleared"), str(services))
    found_by = {s["port"]: s["found_by"] for s in listed}
    check("each service names the scanners that found it",
          found_by == {8802: ["interceptor"], 8803: ["interceptor", "tracer"], 8804: ["tracer"]}, str(found_by))
    merged = next((s for s in listed if s["port"] == 8803), {"id": "", "findings": []})
    findings = {f["scanner"]: (f["auth_method"], f["evidence"]["resource_type"]) for f in merged["findings"]}
    check("8803 keeps each scanner's finding and its evidence",
          findings == {"interceptor": ("basic", "fetch"), "tracer": ("basic", "probe")}, str(findings))
    async with http.get(f"{API}/api/scans/{scan_id}/services/{merged['id']}/urls?scanner=tracer") as r:
        probes = [(u["scanner"], u["url"], u["sources"]) for u in await r.json()] if r.status == 200 else r.status
    check("?scanner=tracer lists the probe alone, with where the URL was found",
          probes == [("tracer", "http://127.0.0.1:8803/api", ["dom: inline script (window.__CONFIG__)"])], str(probes))
    n_events, n_ended = await asyncio.wait_for(notifications, 15)
    check("/notifications delivers scan_completed",
          n_ended == "terminal" and n_events[-1]["scan_id"] == scan_id and n_events[-1]["type"] == "scan_completed")
    return scan_id


async def published_origin(h, http, fast_app):
    """After happy_path, which saw 8803 block: registered as published, the next scan
    publishes it, submits, and keeps that once the entry is removed."""
    print("published origin", flush=True)
    body = {"scheme": "http", "host": "127.0.0.1", "port": 8803, "note": "e2e"}
    async with http.post(f"{API}/api/published-origins", json=body) as r:
        entry = await r.json() if r.status == 201 else {}
        check("registering an origin answers 201 with the entry",
              r.status == 201 and entry.get("id", "").startswith("pub_") and entry.get("removed_at") is None, str(entry))
    async with http.post(f"{API}/api/published-origins", json=body) as r:
        check("registering it again is a 409", r.status == 409, str(r.status))
    scan_id = await create_scan(http, fast_app)
    row = await h.wait_status(scan_id, ENDED, 120)
    check("the scan after the registration completes", row["status"] == "completed", str(row["status"]))
    async with http.get(f"{API}/api/scans/{scan_id}/services") as r:
        svc = next((s for s in await r.json() if s["port"] == 8803), {})
    check("8803 is published, still basic, pointing at the entry",
          (svc.get("auth_method"), svc.get("severity"), (svc.get("published_origin") or {}).get("id"))
          == ("basic", "published", entry.get("id")), str(svc))
    check("each scanner's own finding still says blocker",
          [f["severity"] for f in svc.get("findings", [])] == ["blocker", "blocker"], str(svc.get("findings")))
    events = await h.events(scan_id)
    types = [t for _, t, _ in events]
    check("no blocker_found, and scan_completed counts no blocker",
          "blocker_found" not in types and types[-1] == "scan_completed" and events[-1][2]["blockers"] == 0, str(types))
    async with http.post(f"{API}/api/scans/{scan_id}/submit") as r:
        check("the scan submits", r.status == 200, await r.text())
    async with http.delete(f"{API}/api/published-origins/{entry.get('id')}") as r:
        check("removing the entry is a 204", r.status == 204, str(r.status))
    async with http.get(f"{API}/api/scans/{scan_id}/services") as r:
        svc = next((s for s in await r.json() if s["port"] == 8803), {})
    check("the submitted scan keeps the verdict and sees the entry removed",
          svc.get("severity") == "published" and (svc.get("published_origin") or {}).get("removed_at"),
          str(svc.get("published_origin")))


async def api_restart(h, http, slow_app):
    print("API restart mid-scan", flush=True)
    scan_id = await create_scan(http, slow_app)
    first, _ = await read_sse(http, f"{API}/api/scans/{scan_id}/events", max_events=3, timeout=30)
    if len(first) < 3:
        check("scan streams its first events", False, str(first))
        return
    h.stop_api()
    check("scan keeps running while the API is down", (await h.scan(scan_id))["status"] == "running")
    await asyncio.sleep(12)  # the worker keeps emitting meanwhile
    await h.start_api(http)
    rest, ended = await read_sse(http, f"{API}/api/scans/{scan_id}/events", last_id=first[-1]["seq"], timeout=150)
    all_seqs = seqs(first) + seqs(rest)
    check("Last-Event-ID resume is gap-free and ends terminal",
          ended == "terminal" and all_seqs == list(range(len(all_seqs))), f"{ended} {all_seqs}")
    check("resume includes events emitted while the API was down", len(rest) > 1 and rest[-1]["type"] == "scan_completed")


async def cancel_running(h, http, slow_app, finished_scan, baseline):
    print("cancel", flush=True)
    scan_id = await create_scan(http, slow_app)
    await h.wait_running(scan_id)
    t0 = time.monotonic()
    status = await cancel(http, scan_id)
    row = await h.wait_status(scan_id, ENDED, 20)
    took = time.monotonic() - t0
    # Design: up to one 5s heartbeat plus ~0.1s unwinding. The slack is for a loaded laptop; a broken cancel runs ~50s.
    check("cancelling a running scan: 204, then cancelled promptly",
          status == 204 and row["status"] == "cancelled" and took < 15, f"{status} {row['status']} after {took:.1f}s")
    terminal = [(t, p) for _, t, p in await h.events(scan_id) if t in TERMINAL]
    check("exactly one terminal event, scan_failed reason cancelled", terminal == [("scan_failed", {"reason": "cancelled"})], str(terminal))
    await check_no_chromium_left("no Chromium left after cancel", baseline)
    status = await cancel(http, finished_scan)
    last = (await h.events(finished_scan))[-1]
    check("cancelling a finished scan is a no-op 204",
          status == 204 and last[1] == "scan_completed" and (await h.scan(finished_scan))["status"] == "completed")


async def graceful_shutdown(h, http, slow_app, baseline):
    print("graceful shutdown of both workers mid-scan, then new workers", flush=True)
    scan_id = await create_scan(http, slow_app)
    await h.wait_running(scan_id)
    tracer = await h.wait_job_claimed(scan_id, "tracer")
    check("both scanners' jobs are running", tracer == "running", f"tracer job {tracer}")
    stops = {name: h.stop_worker_gracefully(name) for name in ("A", "T")}
    for name, (sent, how) in stops.items():
        code = await wait_exit(h.workers[name], 30)
        check(f"worker {name} exits cleanly within 30s", sent and code == 0, f"{how}, exit {code}")
    row, jobs = await h.scan(scan_id), await h.jobs(scan_id)
    check("both jobs are back in the queue, the scan still running",
          row["status"] == "running" and jobs == {"interceptor": ("queued", None), "tracer": ("queued", None)},
          f"{row['status']} / {jobs}")
    requeued = sorted(p["scanner"] for _, t, p in await h.events(scan_id) if t == "job_requeued")
    check("each with a job_requeued event", requeued == ["interceptor", "tracer"], str(requeued))
    await check_no_chromium_left("no Chromium left after shutdown", baseline)
    h.start_worker("A", 2)
    h.start_worker("T", 2, scanner="tracer")
    row = await h.wait_status(scan_id, ENDED, 150)
    started = sorted(p["scanner"] for _, t, p in await h.events(scan_id) if t == "job_started")
    check("new workers run both jobs again and the scan completes",
          row["status"] == "completed" and started == ["interceptor", "interceptor", "tracer", "tracer"],
          f"{row['status']} / started {started}")
    # The next scenario starts with no worker running.
    for name in ("A", "T"):
        h.stop_worker_gracefully(name)
        await wait_exit(h.workers[name], 30)


async def shared_queue(h, http, fast_app):
    print("queue without workers, then two interceptor workers and a tracer worker", flush=True)
    queued = [await create_scan(http, fast_app) for _ in range(3)]
    doomed = await create_scan(http, fast_app)
    status = await cancel(http, doomed)
    check("cancelling a queued scan ends it at once", status == 204 and (await h.scan(doomed))["status"] == "cancelled")
    check("with scan_failed reason cancelled", (await h.events(doomed))[-1][1:] == ("scan_failed", {"reason": "cancelled"}))
    await asyncio.sleep(5)
    rows = [await h.scan(s) for s in queued]
    check("scans stay queued while no worker runs", all(r["status"] == "queued" for r in rows), str([r["status"] for r in rows]))
    h.start_worker("B", 1)
    h.start_worker("C", 1)
    h.start_worker("U", 2, scanner="tracer")
    rows = [await h.wait_status(s, ENDED, 120) for s in queued]
    check("all complete once workers start", all(r["status"] == "completed" for r in rows), str([r["status"] for r in rows]))
    # One "Claimed scan" line per job: an interceptor worker's, and the tracer worker's.
    for scanner, logs in (("interceptor", h.worker_log("B") + h.worker_log("C")), ("tracer", h.worker_log("U"))):
        claims = {s: logs.count(f"Claimed scan {s}") for s in queued}
        check(f"each scan's {scanner} job claimed exactly once", all(c == 1 for c in claims.values()), str(claims))
        check(f"the cancelled scan's {scanner} job is never claimed", f"Claimed scan {doomed}" not in logs)
    check("both interceptor workers took scans", len({r["worker_id"] for r in rows}) == 2)


async def hard_kill(h, http, slow_app, baseline):
    print("hard-kill an interceptor worker mid-scan (slow)", flush=True)
    scan_id = await create_scan(http, slow_app)
    row = await h.wait_running(scan_id)
    # Match on the ready line: on Windows the venv python.exe is a launcher, so pids differ.
    victim = next((n for n in ("B", "C") if f"Worker {row['worker_id']} ready" in h.worker_log(n)), None)
    if victim is None:
        check("a worker claims the scan", False, f"{row['status']} {row['worker_id']}")
        return
    h.workers[victim].kill()
    t0 = time.monotonic()
    row = await h.wait_status(scan_id, ENDED, 130)
    jobs = await h.jobs(scan_id)
    check("a surviving worker reaps its job as failed / worker lost",
          jobs["interceptor"] == ("failed", "worker lost"), f"{jobs} after {time.monotonic() - t0:.0f}s")
    # The tracer worker was not touched, so its half of the scan stands.
    check("the scan ends partial, naming the lost scanner",
          (row["status"], row["error"]) == ("partial", "interceptor: worker lost"), f"{row['status']} / {row['error']}")
    _, last_type, last_payload = (await h.events(scan_id))[-1]
    check("with scan_completed, partial, failed_scanners interceptor",
          last_type == "scan_completed" and last_payload.get("partial") is True
          and last_payload.get("failed_scanners") == ["interceptor"], f"{last_type} {last_payload}")
    async with http.post(f"{API}/api/scans/{scan_id}/submit") as r:
        check("a partial scan cannot be submitted", r.status == 409, f"{r.status} {await r.text()}")
    async with http.get(f"{API}/api/apps") as r:
        app = next(a for a in await r.json() if a["id"] == slow_app)
    check("its app reads as failed, to be rescanned",
          (app["exposure_state"], app["last_scan_status"]) == ("failed", "partial"),
          f"{app['exposure_state']} / {app['last_scan_status']}")
    await check_no_chromium_left("no Chromium orphaned by the kill", baseline)


async def multi_process_api(h, http, fast_app):
    print("uvicorn --workers 2", flush=True)
    await h.start_api(http, workers=2)
    await asyncio.sleep(2)
    scan_id = await create_scan(http, fast_app)
    streams = await asyncio.gather(*(read_sse(http, f"{API}/api/scans/{scan_id}/events", timeout=90) for _ in range(6)))
    check("six SSE clients all get scan_completed",
          all(ended == "terminal" and ev[-1]["type"] == "scan_completed" for ev, ended in streams),
          str([ended for _, ended in streams]))


async def run(slow):
    sa_url = os.environ.get("TEST_DATABASE_URL")
    if not sa_url:
        sys.exit("Set TEST_DATABASE_URL to a disposable database; this script truncates it.")
    name = make_url(sa_url).database or ""
    if not name.endswith("_test"):
        sys.exit(f"TEST_DATABASE_URL must name a database ending in '_test' (got {name!r}); refusing to truncate it.")
    busy = ports_in_use()
    if busy:
        sys.exit(f"Ports {busy} are in use; is an API or test site from an earlier run still up?")
    if WINDOWS:
        import ctypes
        ctypes.windll.kernel32.SetConsoleCtrlHandler(None, False)  # workers must not inherit "ignore Ctrl+C"

    h = Harness(sa_url, Path(tempfile.mkdtemp(prefix="e2e_logs_")))
    print(f"logs: {h.logs}", flush=True)
    await h.prepare_database()
    baseline = headless_shells()
    site = await start_site()
    http = aiohttp.ClientSession()
    try:
        await h.start_api(http)
        # A scan has a job per scanner, so it takes a worker of each to finish one.
        h.start_worker("A", 2)
        h.start_worker("T", 2, scanner="tracer")
        fast_app = await create_app(http, "/fast")
        slow_app = await create_app(http, "/slow")
        finished = await happy_path(h, http, fast_app)
        await published_origin(h, http, fast_app)
        await api_restart(h, http, slow_app)
        await cancel_running(h, http, slow_app, finished, baseline)
        await graceful_shutdown(h, http, slow_app, baseline)
        await shared_queue(h, http, fast_app)
        if slow:
            await hard_kill(h, http, slow_app, baseline)
        await multi_process_api(h, http, fast_app)
    finally:
        await http.close()
        h.kill_all()
        for runner in site:
            await runner.cleanup()

    failed = [name for name, ok in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed" + (f"; FAILED: {failed}" if failed else ""))
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description="End-to-end smoke test of the API and worker.")
    parser.add_argument("--slow", action="store_true", help="also hard-kill a worker and wait for the reaper")
    parser.add_argument("--send-ctrl-c", type=int, metavar="PID", help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.send_ctrl_c is not None:
        send_ctrl_c(args.send_ctrl_c)
        return
    sys.exit(asyncio.run(run(args.slow)))


if __name__ == "__main__":
    main()
