"""The per-scan tuning snapshot that travels with each scan row."""

from pydantic import BaseModel, ConfigDict, Field


class ScanSettings(BaseModel):
    """Tuning for one scan.

    Snapshotted onto the scan row when the scan is requested and re-hydrated by
    the worker, so a scan runs with the settings in force when it was asked for,
    not whatever the worker's environment happens to say later."""
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
