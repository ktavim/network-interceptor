"""The deployment agent's API (docs/exposure-design.md, Backend and agent
protocol). The agent pulls: it asks what is waiting for it, reports each step,
and reports the outcome of a phase for the version it worked on. The backend
never calls it.

Every endpoint here will accept only tokens issued to the agent, and an LTM
policy will admit /api/agent/* only from the agent host's address. Like the
rest of the API it is unauthenticated until real identity replaces the /me
stub (phase 6), and must not reach production before then.
"""
from typing import Any, Dict, List

from fastapi import APIRouter, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

from core import exposure_lifecycle
from core.db import ExposureRow

from .models import AgentResultRequest, AgentResultResponse, AgentStepRequest

router = APIRouter(prefix="/agent")


def _session_factory(request: Request) -> async_sessionmaker[AsyncSession]:
    return request.app.state.session_factory


async def _exposure(session: AsyncSession, exposure_id: str) -> ExposureRow:
    exposure = (
        await session.execute(select(ExposureRow).where(ExposureRow.id == exposure_id).with_for_update())
    ).scalar_one_or_none()
    if exposure is None:
        raise HTTPException(status_code=404, detail={"message": "exposure not found"})
    return exposure


@router.get("/pending")
async def pending(request: Request) -> List[Dict[str, Any]]:
    """The exposures waiting on the agent, oldest first: each with its id,
    status and version, and under its status's name what that phase needs."""
    async with _session_factory(request)() as session:
        return await exposure_lifecycle.pending(session)


@router.post("/exposures/{exposure_id}/events", status_code=204)
async def report_step(exposure_id: str, body: AgentStepRequest, request: Request) -> Response:
    """Record a step in the exposure's event log; a repeat of `seq` is ignored."""
    async with _session_factory(request)() as session:
        exposure = await _exposure(session, exposure_id)
        await exposure_lifecycle.record_agent_step(
            session, exposure, seq=body.seq, version=body.version, step=body.step,
            state=body.state, message=body.message, detail=body.detail,
        )
        await session.commit()
    return Response(status_code=204)


@router.post("/exposures/{exposure_id}/result", response_model=AgentResultResponse)
async def report_result(exposure_id: str, body: AgentResultRequest, request: Request) -> AgentResultResponse:
    """Apply the outcome of a phase. `applied` is false, and nothing changes,
    for a result about an older version or a status the exposure has left."""
    if body.outcome == "ok" and body.phase.value == "planning" and body.plan is None:
        raise HTTPException(status_code=422, detail={"message": "a planning result needs its plan"})
    if body.outcome == "ok" and body.phase.value == "deploying" and body.deployment is None:
        raise HTTPException(
            status_code=422, detail={"message": "a deploying result needs the deployment's references"}
        )
    async with _session_factory(request)() as session:
        exposure = await _exposure(session, exposure_id)
        applied = await exposure_lifecycle.apply_agent_result(
            session, exposure, version=body.version, phase=body.phase, ok=body.outcome == "ok",
            plan=body.plan, deployment=body.deployment, step=body.step, message=body.message,
        )
        await session.commit()
    return AgentResultResponse(applied=applied)
