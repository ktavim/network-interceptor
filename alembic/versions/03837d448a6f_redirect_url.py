"""redirect_url

urls.idp_redirect -> urls.redirect_url: the Location of every 3xx, resolved
against the request URL and stripped of query, fragment and userinfo like
urls.url; NULL for any other response. idp_redirect held only IdP handoffs,
and only as a matched host ("x.auth0.com") or host/path fragment, which is not
a URL, so its values are dropped rather than carried into the new column: no
backfill, and non-IdP redirects were never recorded. The downgrade drops the
redirect URLs the same way.

Revision ID: 03837d448a6f
Revises: f3a91c7d2b64
Create Date: 2026-09-29 12:00:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '03837d448a6f'
down_revision: Union[str, Sequence[str], None] = 'f3a91c7d2b64'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.drop_column('urls', 'idp_redirect')
    op.add_column('urls', sa.Column('redirect_url', sa.String(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_column('urls', 'redirect_url')
    op.add_column('urls', sa.Column('idp_redirect', sa.String(), nullable=True))
