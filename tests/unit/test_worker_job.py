"""The hard timeout on both runners in worker.job, with each scanner's engine stubbed. No database."""
import asyncio

import pytest

from core.enums import JobStatus, Scanner
from core.jobs import ClaimedJob
from worker import job as worker_job
from worker.job import USER, Job, run_interceptor_job, run_tracer_job, scan_timeout

TIMEOUT_S = 0.05
TIMED_OUT = "TimeoutError: scan exceeded SCAN_TIMEOUT_S=0.05s"


def _job(scanner: Scanner) -> Job:
    return Job(ClaimedJob("job-1", "scan-1", scanner, "http://x", {}))


@pytest.fixture
def outcomes(monkeypatch):
    """What the runner recorded for its job, in place of the database: (job id, status, error)."""
    recorded = []

    async def record_failure(session_factory, job_id, status, error):
        recorded.append((job_id, status, error))

    monkeypatch.setattr(worker_job, "record_failure", record_failure)
    return recorded


class _HangingMapper:
    """A crawler whose map_website never returns."""

    cleaned_up = False

    def __init__(self, config, on_event=None):
        pass

    async def initialize(self):
        pass

    async def map_website(self):
        await asyncio.sleep(3600)

    async def cleanup(self):
        # Awaits, as closing a browser does: the timeout must not cut it short.
        await asyncio.sleep(0)
        _HangingMapper.cleaned_up = True


@pytest.fixture
def hanging_mapper(monkeypatch):
    _HangingMapper.cleaned_up = False
    monkeypatch.setattr(worker_job, "Mapper", _HangingMapper)
    return _HangingMapper


@pytest.fixture
def hanging_pipeline(monkeypatch):
    """A tracer pipeline that never returns; `cleaned_up` is set once its own cleanup has run."""
    state = {"started": asyncio.Event(), "cleaned_up": False}

    async def run_scan(seeds, settings):
        state["started"].set()
        try:
            await asyncio.sleep(3600)
        finally:
            await asyncio.sleep(0)
            state["cleaned_up"] = True

    monkeypatch.setattr(worker_job, "run_scan", run_scan)
    return state


async def test_interceptor_job_that_never_returns_fails_at_the_timeout(outcomes, hanging_mapper, make_config):
    await run_interceptor_job(_job(Scanner.interceptor), None, make_config(), TIMEOUT_S)
    assert outcomes == [("job-1", JobStatus.failed, TIMED_OUT)]
    assert hanging_mapper.cleaned_up


async def test_tracer_job_that_never_returns_fails_at_the_timeout(outcomes, hanging_pipeline):
    await run_tracer_job(_job(Scanner.tracer), None, TIMEOUT_S)
    assert outcomes == [("job-1", JobStatus.failed, TIMED_OUT)]
    assert hanging_pipeline["cleaned_up"]


async def test_scan_within_the_timeout_is_left_alone():
    async with scan_timeout(60):
        await asyncio.sleep(0)


async def test_engines_own_timeout_error_is_not_the_scan_timeout(outcomes, monkeypatch):
    async def run_scan(seeds, settings):
        raise TimeoutError("probe timed out")

    monkeypatch.setattr(worker_job, "run_scan", run_scan)
    await run_tracer_job(_job(Scanner.tracer), None, 60)
    assert outcomes == [("job-1", JobStatus.failed, "TimeoutError: probe timed out")]


async def test_cancel_before_the_timeout_is_recorded_as_the_cancel(outcomes, hanging_pipeline):
    job = _job(Scanner.tracer)
    job.task = asyncio.create_task(run_tracer_job(job, None, 60))
    await hanging_pipeline["started"].wait()

    job.request_cancel(USER)
    await asyncio.wait({job.task})

    assert job.task.cancelled()
    assert outcomes == [("job-1", JobStatus.cancelled, "cancelled")]
    assert hanging_pipeline["cleaned_up"]
