"""The per-scan tuning snapshot that travels with each scan's tracer job."""

import os
from collections.abc import Mapping

from pydantic import BaseModel, ConfigDict, Field

# The environment variable behind each field, named as config-tracer named them.
_ENV_VARS = {
    "nav_timeout_ms": "SCAN_NAV_TIMEOUT_MS",
    "wait_after_load_ms": "SCAN_WAIT_AFTER_LOAD_MS",
    "interact_budget_ms": "SCAN_INTERACT_BUDGET_MS",
    "follow_links": "SCAN_FOLLOW_LINKS",
    "max_pages": "SCAN_MAX_PAGES",
    "probe_timeout_s": "PROBE_TIMEOUT_S",
    "probe_concurrency": "PROBE_CONCURRENCY",
    "dns_timeout_s": "DNS_TIMEOUT_S",
    "dns_concurrency": "DNS_CONCURRENCY",
}


class ScanSettings(BaseModel):
    """Tuning for one scan.

    Snapshotted onto the scan's tracer job when the scan is requested and
    re-hydrated by the worker, so a scan runs with the settings in force when it
    was asked for, not whatever the worker's environment happens to say later."""
    model_config = ConfigDict(frozen=True, extra="forbid")

    nav_timeout_ms: int = Field(30000, ge=0, description="Playwright navigation timeout")
    wait_after_load_ms: int = Field(5000, ge=0, description="Extra idle wait for lazy XHRs, applied before and after interactions")
    interact_budget_ms: int = Field(8000, ge=0, description="Per-page budget for safe scroll/hover/click interactions")
    follow_links: bool = Field(False, description="Discover and crawl same-origin links")
    max_pages: int = Field(1, ge=1, description="Cap on pages visited")
    probe_timeout_s: float = Field(5.0, gt=0, description="Per-URL auth-probe timeout")
    probe_concurrency: int = Field(10, ge=1, description="Max concurrent probe requests")
    dns_timeout_s: float = Field(3.0, gt=0, description="Per-host DNS resolution timeout")
    dns_concurrency: int = Field(20, ge=1, description="Max concurrent DNS lookups")

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> "ScanSettings":
        """The settings the environment asks for: each field from its variable
        (`max_pages` <- SCAN_MAX_PAGES, `probe_timeout_s` <- PROBE_TIMEOUT_S),
        or its default when the variable is unset. A value its field refuses
        raises pydantic's ValidationError."""
        environ = os.environ if environ is None else environ
        return cls(**{
            field: environ[var].strip() for field, var in _ENV_VARS.items() if var in environ
        })
