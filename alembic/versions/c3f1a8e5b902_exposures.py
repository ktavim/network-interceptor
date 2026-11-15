"""exposures

Publishing a submitted app through the F5 (docs/exposure-design.md): one
exposure per submission, its VIP groups and their members, and its event log.
The published-origins registry gains the URL of the VIP that publishes each
origin, which other apps' rewrite maps read.

Revision ID: c3f1a8e5b902
Revises: b7c2d9e4f1a3
Create Date: 2026-11-15

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'c3f1a8e5b902'
down_revision: Union[str, Sequence[str], None] = 'b7c2d9e4f1a3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# core.enums.ExposureStatus and CLOSED_EXPOSURE_STATUSES at this revision.
_EXPOSURE_STATUSES = (
    "('grouping', 'planning', 'awaiting_confirmation', 'deploying', 'deployed', "
    "'failed', 'cancelling', 'cancelled', 'superseded')"
)
_CLOSED_EXPOSURE_STATUSES = "('deployed', 'cancelled', 'superseded')"


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('published_origins', sa.Column('url', sa.String(), nullable=True))

    op.create_table('exposures',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('app_id', sa.String(), nullable=False),
    sa.Column('scan_id', sa.String(), nullable=False),
    sa.Column('status', sa.String(), nullable=False),
    sa.Column('version', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('first_planned_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('superseded_by_id', sa.String(), nullable=True),
    sa.CheckConstraint(f"status IN {_EXPOSURE_STATUSES}", name='ck_exposures_status'),
    sa.ForeignKeyConstraint(['app_id'], ['apps.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(
        ['superseded_by_id'], ['exposures.id'], ondelete='SET NULL',
        name='fk_exposures_superseded_by_id',
    ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('scan_id'),
    )
    op.create_index(op.f('ix_exposures_app_id'), 'exposures', ['app_id'], unique=False)
    op.create_index(op.f('ix_exposures_status'), 'exposures', ['status'], unique=False)
    # At most one open exposure per app.
    op.create_index(
        'uq_exposures_open_per_app', 'exposures', ['app_id'], unique=True,
        postgresql_where=sa.text(f"status NOT IN {_CLOSED_EXPOSURE_STATUSES}"),
    )

    op.create_table('exposure_groups',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('exposure_id', sa.String(), nullable=False),
    sa.Column('position', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['exposure_id'], ['exposures.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('exposure_id', 'position', name='uq_exposure_groups_position'),
    sa.UniqueConstraint('exposure_id', 'id', name='uq_exposure_groups_exposure_id'),
    )

    op.create_table('exposure_group_members',
    sa.Column('exposure_id', sa.String(), nullable=False),
    sa.Column('service_id', sa.String(), nullable=False),
    sa.Column('group_id', sa.String(), nullable=False),
    sa.ForeignKeyConstraint(['exposure_id'], ['exposures.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(['service_id'], ['services.id'], ondelete='CASCADE'),
    sa.ForeignKeyConstraint(
        ['exposure_id', 'group_id'], ['exposure_groups.exposure_id', 'exposure_groups.id'],
        ondelete='CASCADE', name='fk_exposure_group_members_group',
    ),
    sa.PrimaryKeyConstraint('exposure_id', 'service_id'),
    )
    op.create_index(
        op.f('ix_exposure_group_members_group_id'), 'exposure_group_members', ['group_id'],
        unique=False,
    )

    op.create_table('exposure_events',
    sa.Column('exposure_id', sa.String(), nullable=False),
    sa.Column('seq', sa.Integer(), nullable=False),
    sa.Column('ts', sa.BigInteger(), nullable=False),
    sa.Column('type', sa.String(), nullable=False),
    sa.Column('actor', sa.String(), nullable=False),
    sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.ForeignKeyConstraint(['exposure_id'], ['exposures.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('exposure_id', 'seq'),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table('exposure_events')
    op.drop_index(op.f('ix_exposure_group_members_group_id'), table_name='exposure_group_members')
    op.drop_table('exposure_group_members')
    op.drop_table('exposure_groups')
    op.drop_index('uq_exposures_open_per_app', table_name='exposures')
    op.drop_index(op.f('ix_exposures_status'), table_name='exposures')
    op.drop_index(op.f('ix_exposures_app_id'), table_name='exposures')
    op.drop_table('exposures')
    op.drop_column('published_origins', 'url')
