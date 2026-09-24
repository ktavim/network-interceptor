"""sent_auth_scheme

urls.sent_auth_scheme: the auth-scheme word of the Authorization header the
client sent ("Basic", "Digest", "Negotiate"), or NULL. Only the scheme token
is ever stored, never the credentials after it (auth_analyzer.sent_auth_scheme),
so a sent-credential finding has evidence again without the headers snippet
that 886021cc2cd0 dropped. No backfill: existing rows kept no headers.

Revision ID: 55e105b9349e
Revises: 886021cc2cd0
Create Date: 2026-09-24 18:08:27.135991

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '55e105b9349e'
down_revision: Union[str, Sequence[str], None] = '886021cc2cd0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('urls', sa.Column('sent_auth_scheme', sa.String(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('urls', 'sent_auth_scheme')
