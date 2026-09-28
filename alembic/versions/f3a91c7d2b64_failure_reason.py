"""failure_reason

urls.failure_reason: the browser's error text for a captured request that got
no response ("net::ERR_NAME_NOT_RESOLVED", "net::ERR_ABORTED"), whose
status_code is 0; NULL for one that got a response. No backfill: the reason
was only ever logged before.

Revision ID: f3a91c7d2b64
Revises: 8e8d01bec9cc
Create Date: 2026-09-28 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'f3a91c7d2b64'
down_revision: Union[str, Sequence[str], None] = '8e8d01bec9cc'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('urls', sa.Column('failure_reason', sa.String(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('urls', 'failure_reason')
