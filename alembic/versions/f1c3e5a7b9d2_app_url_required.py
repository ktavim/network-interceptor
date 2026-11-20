"""app url required

Every app has a URL: creating one requires it, and its scans and its
exposure's VIP are built from it. The column says so too. Apps created before
the URL was required may lack one; the upgrade stops and names them, rather
than guess a URL, so each can be given its real one first.

Revision ID: f1c3e5a7b9d2
Revises: e8b2d4f6a1c3
Create Date: 2026-11-16

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision: str = 'f1c3e5a7b9d2'
down_revision: Union[str, Sequence[str], None] = 'e8b2d4f6a1c3'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    missing = op.get_bind().execute(
        sa.text("SELECT id, name FROM apps WHERE url IS NULL OR btrim(url) = '' ORDER BY name")
    ).all()
    if missing:
        names = ", ".join(f"{name} ({app_id})" for app_id, name in missing)
        raise RuntimeError(
            f"{len(missing)} app(s) have no URL: {names}. Set each one's URL "
            "(UPDATE apps SET url = '...' WHERE id = '...'), then upgrade again."
        )
    op.alter_column('apps', 'url', existing_type=sa.String(), nullable=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.alter_column('apps', 'url', existing_type=sa.String(), nullable=True)
