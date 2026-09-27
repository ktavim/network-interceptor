"""scans worker lease

scans.worker_id, heartbeat_at, cancel_requested_at: the worker's claim on a
running scan, its liveness, and the API's cancel request.

Revision ID: c7e2a9d41f06
Revises: a396fc238c9b
Create Date: 2026-09-27 18:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c7e2a9d41f06'
down_revision: Union[str, Sequence[str], None] = 'a396fc238c9b'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('scans', sa.Column('worker_id', sa.String(), nullable=True))
    op.add_column('scans', sa.Column('heartbeat_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('scans', sa.Column('cancel_requested_at', sa.DateTime(timezone=True), nullable=True))
    # Scans left by the in-process crawler have no heartbeat, so the reaper would never fail them.
    op.execute(
        "UPDATE scans SET status = 'failed', completed_at = now(), error = 'server restarted' "
        "WHERE status IN ('queued', 'running')"
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('scans', 'cancel_requested_at')
    op.drop_column('scans', 'heartbeat_at')
    op.drop_column('scans', 'worker_id')
