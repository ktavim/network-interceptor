"""exposure deploys

Deploying an exposure: the agent's references on the F5 and in DNS once it is
deployed, and, on each published-origins entry a deploy registered, the
exposure that registered it.

Revision ID: e8b2d4f6a1c3
Revises: d5a7c1e9f3b0
Create Date: 2026-11-16

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'e8b2d4f6a1c3'
down_revision: Union[str, Sequence[str], None] = 'd5a7c1e9f3b0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('exposures', sa.Column('deployment', postgresql.JSONB(astext_type=sa.Text()), nullable=True))
    op.add_column('exposures', sa.Column('deployed_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('published_origins', sa.Column('exposure_id', sa.String(), nullable=True))
    op.create_foreign_key(
        'fk_published_origins_exposure_id', 'published_origins', 'exposures',
        ['exposure_id'], ['id'], ondelete='SET NULL',
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_constraint('fk_published_origins_exposure_id', 'published_origins', type_='foreignkey')
    op.drop_column('published_origins', 'exposure_id')
    op.drop_column('exposures', 'deployed_at')
    op.drop_column('exposures', 'deployment')
