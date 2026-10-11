"""published origins

A registry of origins already published through the F5, and the fourth
services.severity value, "published", which only the registry produces
(core.jobs._recompute_services). One new table, one nullable column on
services pointing at the entry that published it, and the severity CHECK
widened by one value.

Revision ID: b7c2d9e4f1a3
Revises: a6e5654e0d44
Create Date: 2026-10-09

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'b7c2d9e4f1a3'
down_revision: Union[str, Sequence[str], None] = 'a6e5654e0d44'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# core.enums.Severity before and at this revision.
_SEVERITIES_BEFORE = "('blocker', 'review', 'cleared')"
_SEVERITIES = "('blocker', 'review', 'cleared', 'published')"


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('published_origins',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('scheme', sa.String(), nullable=False),
    sa.Column('host', sa.String(), nullable=False),
    sa.Column('port', sa.Integer(), nullable=False),
    sa.Column('note', sa.String(), nullable=False),
    sa.Column('added_by', sa.String(), nullable=False),
    sa.Column('added_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('removed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('removed_by', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    # One active entry per origin; a removed one does not block re-adding it.
    op.create_index(
        'uq_published_origins_active', 'published_origins', ['scheme', 'host', 'port'],
        unique=True, postgresql_where=sa.text('removed_at IS NULL'),
    )
    op.add_column('services', sa.Column('published_origin_id', sa.String(), nullable=True))
    op.create_foreign_key(
        'fk_services_published_origin_id', 'services', 'published_origins',
        ['published_origin_id'], ['id'], ondelete='SET NULL',
    )
    op.create_index(op.f('ix_services_published_origin_id'), 'services', ['published_origin_id'], unique=False)
    op.drop_constraint('ck_services_severity', 'services', type_='check')
    op.create_check_constraint('ck_services_severity', 'services', f"severity IN {_SEVERITIES}")


def downgrade() -> None:
    """Downgrade schema."""
    # Before the CHECK narrows: the rows the registry published go back to
    # what their method says, core.translate.severity_for in SQL.
    op.execute(
        "UPDATE services SET severity = CASE "
        "WHEN auth_method IN ('ntlm', 'basic', 'other') THEN 'blocker' "
        "WHEN auth_method IN ('kerberos', 'bearer', 'oauth', 'login_redirect', 'api_key', 'unauthenticated') "
        "THEN 'cleared' "
        "ELSE 'review' END "
        "WHERE severity = 'published'"
    )
    op.drop_constraint('ck_services_severity', 'services', type_='check')
    op.create_check_constraint('ck_services_severity', 'services', f"severity IN {_SEVERITIES_BEFORE}")
    op.drop_index(op.f('ix_services_published_origin_id'), table_name='services')
    op.drop_constraint('fk_services_published_origin_id', 'services', type_='foreignkey')
    op.drop_column('services', 'published_origin_id')
    op.drop_index('uq_published_origins_active', table_name='published_origins')
    op.drop_table('published_origins')
