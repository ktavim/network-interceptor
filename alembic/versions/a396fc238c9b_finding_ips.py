"""finding ips

findings.ips: the addresses the finding's host resolved to at scan time, the
F5 pool members for the origin. No backfill: a lookup today is not the scan's.

Revision ID: a396fc238c9b
Revises: 55e105b9349e
Create Date: 2026-09-27 02:41:30.574018

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


# revision identifiers, used by Alembic.
revision: str = 'a396fc238c9b'
down_revision: Union[str, Sequence[str], None] = '55e105b9349e'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('findings', sa.Column('ips', postgresql.ARRAY(sa.String()), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('findings', 'ips')
