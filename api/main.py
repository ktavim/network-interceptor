import asyncio
import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config_loader import Config, FormConfig, load_config

from .db import init_db, make_engine, make_session_factory, sweep_stale_scans
from .routes_apps import router as apps_router
from .routes_events import router as events_router
from .routes_scans import router as scans_router
from .sse import EventBus

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


def _default_base_config() -> Config:
    return Config(
        start_url="https://placeholder.invalid",  # always overridden per-request
        max_depth=3,
        max_clicks_per_page=20,
        wait_timeout=30000,
        network_idle_timeout=2000,
        form_filling=FormConfig(enabled=True, fill_delay=100, defaults={}),
        exclude_patterns=None,
        login=None,
    )


def _load_base_config() -> Config:
    config_path = os.environ.get("SCRAPER_CONFIG_PATH", "./config.json")
    if not os.path.exists(config_path):
        logger.info("No config file at %s; using built-in defaults", config_path)
        return _default_base_config()
    try:
        return load_config(config_path)
    except Exception as e:
        logger.warning("Failed to load config from %s (%s); using built-in defaults", config_path, e)
        return _default_base_config()


def _check_single_worker() -> None:
    """In-memory state (scan_tasks, SSE subscribers, semaphore) is per-process.
    Refuse to start with multiple workers — silent races would corrupt state."""
    web_concurrency = os.environ.get("WEB_CONCURRENCY")
    if web_concurrency and web_concurrency.isdigit() and int(web_concurrency) > 1:
        raise RuntimeError(
            f"WEB_CONCURRENCY={web_concurrency}: this server uses in-memory state and "
            "must run with a single worker. Run uvicorn with --workers 1."
        )


@asynccontextmanager
async def lifespan(app: FastAPI):
    _check_single_worker()

    app.state.base_config = _load_base_config()
    max_parallel = int(os.environ.get("SCRAPER_MAX_PARALLEL", "2"))
    app.state.semaphore = asyncio.Semaphore(max_parallel)

    engine = make_engine()
    session_factory = make_session_factory(engine)
    await init_db(engine)
    app.state.engine = engine
    app.state.session_factory = session_factory

    swept = await sweep_stale_scans(session_factory)
    if swept:
        logger.warning("Marked %d stale scans as failed (server restarted)", swept)

    app.state.event_bus = EventBus(session_factory)
    app.state.background_tasks: set[asyncio.Task] = set()
    app.state.scan_tasks: dict[str, asyncio.Task] = {}

    logger.info("Backend ready (max_parallel=%d)", max_parallel)
    try:
        yield
    finally:
        tasks = list(app.state.background_tasks)
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await engine.dispose()


app = FastAPI(
    title="Network Interceptor API",
    description="Pre-exposure scanner.",
    version="2.0.0",
    lifespan=lifespan,
)

_default_origins = "http://localhost:4200"
_origins = [
    o.strip()
    for o in os.environ.get("CORS_ALLOW_ORIGINS", _default_origins).split(",")
    if o.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(scans_router, prefix="/api")
app.include_router(apps_router, prefix="/api")
app.include_router(events_router, prefix="/api")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
