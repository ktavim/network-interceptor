"""Tests for core.jobs.scan_status: a scan's status, derived from its jobs'."""
import pytest

from core.enums import JobStatus, ScanStatus
from core.jobs import scan_status

Q, R, C, F, X = (
    JobStatus.queued,
    JobStatus.running,
    JobStatus.completed,
    JobStatus.failed,
    JobStatus.cancelled,
)


@pytest.mark.parametrize("jobs, expected", [
    ([Q], ScanStatus.queued),
    ([Q, Q], ScanStatus.queued),
    ([R], ScanStatus.running),
    ([Q, R], ScanStatus.running),
    # A finished job does not end the scan while another is still to run.
    ([C, Q], ScanStatus.running),
    ([F, R], ScanStatus.running),
    ([C], ScanStatus.completed),
    ([C, C], ScanStatus.completed),
    ([C, F], ScanStatus.partial),
    ([F, C], ScanStatus.partial),
    ([F], ScanStatus.failed),
    ([F, F], ScanStatus.failed),
])
def test_status_follows_the_jobs(jobs, expected):
    assert scan_status(jobs, cancel_requested=False) == expected


@pytest.mark.parametrize("jobs", [[X], [X, X], [C, X], [F, X], [C, C], [C, F], [F, F]])
def test_a_cancel_request_makes_a_finished_scan_cancelled(jobs):
    # Whatever the jobs came to, including one that completed before the
    # request, or between the request and its worker's next heartbeat.
    assert scan_status(jobs, cancel_requested=True) == ScanStatus.cancelled


@pytest.mark.parametrize("jobs, expected", [
    ([Q, Q], ScanStatus.queued),
    ([R, X], ScanStatus.running),
    ([C, R], ScanStatus.running),
])
def test_a_cancel_request_waits_for_the_running_jobs(jobs, expected):
    assert scan_status(jobs, cancel_requested=True) == expected


@pytest.mark.parametrize("jobs", [[X], [C, X], [F, X]])
def test_a_cancelled_job_means_a_cancelled_scan(jobs):
    assert scan_status(jobs, cancel_requested=False) == ScanStatus.cancelled
