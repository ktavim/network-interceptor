"""exposure plans

Planning, confirming and failing an exposure: the agent's plan and its hash,
who confirmed it, and where a phase failed. The agent's step reports carry its
own sequence number, unique per exposure, so a repeat is recorded once. An
exposure that is deploying or cancelling no longer counts as its app's one
open exposure: a new submission leaves it to finish.

Revision ID: d5a7c1e9f3b0
Revises: c3f1a8e5b902
Create Date: 2026-11-16

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'd5a7c1e9f3b0'
down_revision: Union[str, Sequence[str], None] = 'c3f1a8e5b902'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_PHASES = "('planning', 'deploying', 'cancelling')"
_CLOSED = "('deployed', 'cancelled', 'superseded')"
_NON_EXCLUSIVE = "('deployed', 'cancelled', 'superseded', 'deploying', 'cancelling')"


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('exposures', sa.Column('plan', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('exposures', sa.Column('plan_hash', sa.String(), nullable=True))
    op.add_column('exposures', sa.Column('plan_version', sa.Integer(), nullable=True))
    op.add_column('exposures', sa.Column('confirmed_by', sa.String(), nullable=True))
    op.add_column('exposures', sa.Column('confirmed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('exposures', sa.Column('failed_phase', sa.String(), nullable=True))
    op.add_column('exposures', sa.Column('failed_step', sa.String(), nullable=True))
    op.add_column('exposures', sa.Column('failed_message', sa.Text(), nullable=True))
    op.create_check_constraint(
        'ck_exposures_failed_phase', 'exposures', f"failed_phase IN {_PHASES}"
    )
    op.drop_index('uq_exposures_open_per_app', table_name='exposures')
    op.create_index(
        'uq_exposures_open_per_app', 'exposures', ['app_id'], unique=True,
        postgresql_where=sa.text(f"status NOT IN {_NON_EXCLUSIVE}"),
    )

    op.add_column('exposure_events', sa.Column('agent_seq', sa.Integer(), nullable=True))
    op.create_index(
        'uq_exposure_events_agent_seq', 'exposure_events', ['exposure_id', 'agent_seq'], unique=True,
        postgresql_where=sa.text('agent_seq IS NOT NULL'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index('uq_exposure_events_agent_seq', table_name='exposure_events')
    op.drop_column('exposure_events', 'agent_seq')
    op.drop_index('uq_exposures_open_per_app', table_name='exposures')
    # The narrower index allows one open exposure per app, where this
    # revision lets one deploying or cancelling stand beside a newer one.
    # Every open one but each app's newest is closed as superseded.
    op.execute(
        f"""
        UPDATE exposures SET status = 'superseded'
        WHERE status NOT IN {_CLOSED}
          AND id NOT IN (
            SELECT DISTINCT ON (app_id) id FROM exposures
            WHERE status NOT IN {_CLOSED}
            ORDER BY app_id, created_at DESC
          )
        """
    )
    op.create_index(
        'uq_exposures_open_per_app', 'exposures', ['app_id'], unique=True,
        postgresql_where=sa.text(f"status NOT IN {_CLOSED}"),
    )
    op.drop_constraint('ck_exposures_failed_phase', 'exposures', type_='check')
    for column in (
        'failed_message', 'failed_step', 'failed_phase', 'confirmed_at', 'confirmed_by',
        'plan_version', 'plan_hash', 'plan',
    ):
        op.drop_column('exposures', column)
