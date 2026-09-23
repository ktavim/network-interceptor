"""urls

Revision ID: ba4f0d77c452
Revises: d53c03d0e333
Create Date: 2026-09-20 13:48:43.921395

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'ba4f0d77c452'
down_revision: Union[str, Sequence[str], None] = 'd53c03d0e333'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('urls',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('finding_id', sa.String(), nullable=False),
    sa.Column('method', sa.String(), nullable=False),
    sa.Column('url', sa.String(), nullable=False),
    sa.Column('resource_type', sa.String(), nullable=False),
    sa.Column('status_code', sa.Integer(), nullable=False),
    sa.Column('auth_method', sa.String(), nullable=False),
    sa.Column('auth_challenge', sa.Text(), nullable=True),
    sa.Column('idp_redirect', sa.String(), nullable=True),
    sa.Column('source_url', sa.String(), nullable=False),
    sa.ForeignKeyConstraint(['finding_id'], ['findings.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_urls_finding_id'), 'urls', ['finding_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_urls_finding_id'), table_name='urls')
    op.drop_table('urls')
