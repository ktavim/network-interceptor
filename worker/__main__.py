"""Scan worker: claims queued interceptor jobs from Postgres and crawls their scans. Run with `python -m worker`."""
import asyncio
import logging
import os
import signal
import socket
import sys
import uuid
from typing import Dict, List

from dotenv import load_dotenv
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from config_loader import Config, FormConfig, load_config
from core.db import make_engine, make_session_factory
from core.enums import JobStatus, Scanner
from core.jobs import claim_next, heartbeat, reap_stale, release

from .job import LEASE_LOST, SHUTDOWN, USER, Job, record_failure, run_scan_job

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("worker")

CLAIM_INTERVAL = 2.0
HEARTBEAT_INTERVAL = 5.0
REAP_INTERVAL = 30.0
# Under OpenShift's default 30s termination grace period.
SHUTDOWN_TIMEOUT = 20.0


def _default_base_config() -> Config:
    return Config(
        start_url="https://placeholder.invalid",  # always overridden per-scan
        max_depth=3,
        max_clicks_per_page=20,
        wait_timeout=30000,
        network_idle_timeout=2000,
        form_filling=FormConfig(enabled=True, fill_delay=100, defaults={}),
        exclude_patterns=None,
        login=None,
    )


def _load_base_config() -> Config:
    config_path = os.environ.get("CRAWLER_CONFIG_PATH", "./config.json")
    if not os.path.exists(config_path):
        logger.info("No config file at %s; using built-in defaults", config_path)
        return _default_base_config()
    try:
        return load_config(config_path)
    except Exception as e:
        logger.warning("Failed to load config from %s (%s); using built-in defaults", config_path, e)
        return _default_base_config()


class Worker:
    def __init__(
        self,
        session_factory: async_sessionmaker[AsyncSession],
        base_config: Config,
        max_parallel: int,
    ):
        self.id = f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:6]}"
        self.session_factory = session_factory
        self.base_config = base_config
        self.max_parallel = max_parallel
        # By job id.
        self.jobs: Dict[str, Job] = {}
        self.shutting_down = False

    async def _slot(self) -> None:
        while not self.shutting_down:
            try:
                claim = await claim_next(self.session_factory, Scanner.interceptor, self.id)
            except Exception as e:
                logger.warning("Claim failed: %s", e)
                claim = None
            if claim is None:
                await asyncio.sleep(CLAIM_INTERVAL)
                continue
            if self.shutting_down:
                await release(self.session_factory, claim.id)
                return

            logger.info("Claimed scan %s (%s)", claim.scan_id, claim.url)
            job = Job(claim)
            job.task = asyncio.create_task(
                run_scan_job(job, self.base_config, self.session_factory),
                name=f"scan-{claim.scan_id}",
            )
            self.jobs[claim.id] = job
            # wait(), not await: cancelling the slot must not cancel the job.
            await asyncio.wait({job.task})
            del self.jobs[claim.id]

            if not job.task.cancelled() and job.task.exception() is not None:
                exc = job.task.exception()
                logger.error("Job for scan %s crashed", claim.scan_id, exc_info=exc)
                try:
                    await record_failure(
                        self.session_factory, claim.id, JobStatus.failed, f"{exc.__class__.__name__}: {exc}"
                    )
                except Exception as e:
                    logger.warning("Could not record the crash of scan %s: %s", claim.scan_id, e)
            else:
                logger.info("Scan %s done", claim.scan_id)

    async def _heartbeat_loop(self) -> None:
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            live = [job_id for job_id, job in self.jobs.items() if not job.task.done()]
            try:
                held = await heartbeat(self.session_factory, live)
            except Exception as e:
                logger.warning("Heartbeat failed: %s", e)
                continue
            for job_id in live:
                job = self.jobs.get(job_id)
                # A finalizing job ends itself, and is past cancelling.
                if job is None or job.finalizing:
                    continue
                if job_id not in held:
                    logger.warning("Scan %s: its job was ended by someone else; stopping it", job.claim.scan_id)
                    job.request_cancel(LEASE_LOST)
                elif held[job_id] is not None:
                    logger.info("Cancel requested for scan %s", job.claim.scan_id)
                    job.request_cancel(USER)

    async def _reap_loop(self) -> None:
        while True:
            try:
                for job_id in await reap_stale(self.session_factory, list(self.jobs)):
                    logger.warning("Reaped job %s: its worker stopped heartbeating", job_id)
            except Exception as e:
                logger.warning("Reaper failed: %s", e)
            await asyncio.sleep(REAP_INTERVAL)

    async def run(self) -> int:
        """Run until cancelled; returns 1 if a slot or loop dies."""
        slots = [asyncio.create_task(self._slot(), name=f"slot-{i}") for i in range(self.max_parallel)]
        loops = [
            asyncio.create_task(self._heartbeat_loop(), name="heartbeat"),
            asyncio.create_task(self._reap_loop(), name="reaper"),
        ]
        try:
            done, _ = await asyncio.wait(slots + loops, return_when=asyncio.FIRST_EXCEPTION)
            for task in done:
                if not task.cancelled() and task.exception() is not None:
                    logger.error("%s died", task.get_name(), exc_info=task.exception())
            return 1
        finally:
            await self._shutdown(slots, loops)

    async def _shutdown(self, slots: List[asyncio.Task], loops: List[asyncio.Task]) -> None:
        self.shutting_down = True
        if self.jobs:
            logger.info("Shutting down; stopping %d scan(s)", len(self.jobs))
        for job in list(self.jobs.values()):
            job.request_cancel(SHUTDOWN)
        # A slot returns once its job has recorded its outcome.
        pending = [t for t in slots if not t.done()]
        if pending:
            await asyncio.wait(pending, timeout=SHUTDOWN_TIMEOUT)
        stragglers = slots + loops + [job.task for job in self.jobs.values()]
        for task in stragglers:
            task.cancel()
        await asyncio.gather(*stragglers, return_exceptions=True)


async def main() -> int:
    base_config = _load_base_config()
    max_parallel = int(os.environ.get("CRAWLER_MAX_PARALLEL", "2"))
    engine = make_engine()
    worker = Worker(make_session_factory(engine), base_config, max_parallel)

    if sys.platform != "win32":
        asyncio.get_running_loop().add_signal_handler(signal.SIGTERM, asyncio.current_task().cancel)

    logger.info("Worker %s ready (max_parallel=%d)", worker.id, max_parallel)
    try:
        return await worker.run()
    finally:
        await engine.dispose()


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except (KeyboardInterrupt, asyncio.CancelledError):
        logger.info("Worker stopped")
