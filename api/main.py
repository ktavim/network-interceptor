import asyncio
import logging
import os
from contextlib import asynccontextmanager

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from config_tracer.settings import ScanSettings
from core.db import make_engine, make_session_factory

from .routes_apps import router as apps_router
from .routes_events import router as events_router
from .routes_published_origins import router as published_origins_router
from .routes_scans import router as scans_router
from .routes_me import router as me_router
from .sse import EventBus

load_dotenv()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # The tracer's tuning, read from the environment once; each scan's tracer
    # job gets a snapshot of it. A bad value stops the API here, not a scan later.
    app.state.tracer_settings = ScanSettings.from_env()

    engine = make_engine()
    session_factory = make_session_factory(engine)
    app.state.engine = engine
    app.state.session_factory = session_factory

    app.state.event_bus = EventBus(session_factory)
    listener = asyncio.create_task(app.state.event_bus.run(), name="event-listener")

    logger.info("Backend ready")
    try:
        yield
    finally:
        listener.cancel()
        await asyncio.gather(listener, return_exceptions=True)
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
app.include_router(published_origins_router, prefix="/api")
app.include_router(me_router, prefix="/api")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}
