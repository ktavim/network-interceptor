"""evidence_url

Findings point at the url row that is their evidence (the captured request
whose authentication classification won) instead of carrying a copy of its
status and page plus a raw request-headers snippet. The snippet is dropped
outright: it stored live credentials, and a redacted one would say little
beyond auth_method.

Revision ID: 886021cc2cd0
Revises: ba4f0d77c452
Create Date: 2026-09-24 16:30:00.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '886021cc2cd0'
down_revision: Union[str, Sequence[str], None] = 'ba4f0d77c452'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column('findings', sa.Column('evidence_url_id', sa.String(), nullable=True))
    op.create_index(op.f('ix_findings_evidence_url_id'), 'findings', ['evidence_url_id'], unique=False)
    # Best-effort backfill for existing findings: the url row that matches the
    # status and page the finding copied from its winning request. Capture
    # order was never stored, so among several matches prefer one carrying the
    # finding's own auth method (the winner did, unless the finding was since
    # corrected by hand), then the listing order of the urls endpoint.
    # Runs before the foreign key exists: that constraint is deferred, and a
    # check left pending by this UPDATE would block the ALTER TABLEs below
    # ("pending trigger events"). ADD CONSTRAINT validates the rows anyway.
    op.execute(
        """
        UPDATE findings f SET evidence_url_id = (
            SELECT u.id FROM urls u
            WHERE u.finding_id = f.id
              AND u.status_code = f.status_code
              AND u.page_url = f.first_seen_on_page
            ORDER BY (u.auth_method = f.auth_method) DESC, u.url, u.method
            LIMIT 1
        )
        """
    )
    # findings -> urls -> findings is a cycle. Deferred so a scan's findings can
    # be inserted ahead of the url rows they point to within one transaction.
    op.create_foreign_key(
        'fk_findings_evidence_url_id', 'findings', 'urls',
        ['evidence_url_id'], ['id'], ondelete='SET NULL',
        deferrable=True, initially='DEFERRED',
    )
    op.drop_column('findings', 'first_seen_on_page')
    op.drop_column('findings', 'headers_snippet')
    op.drop_column('findings', 'status_code')


def downgrade() -> None:
    """Downgrade schema.

    status_code and first_seen_on_page are restored from the evidence row;
    headers_snippet cannot be and comes back empty.
    """
    op.add_column('findings', sa.Column('status_code', sa.Integer(), nullable=False, server_default='0'))
    op.add_column('findings', sa.Column('headers_snippet', sa.Text(), nullable=False, server_default=''))
    op.add_column('findings', sa.Column('first_seen_on_page', sa.String(), nullable=False, server_default=''))
    # Constraint first, for the same reason upgrade backfills before adding it.
    op.drop_constraint('fk_findings_evidence_url_id', 'findings', type_='foreignkey')
    op.execute(
        """
        UPDATE findings f SET status_code = u.status_code, first_seen_on_page = u.page_url
        FROM urls u WHERE u.id = f.evidence_url_id
        """
    )
    # The original columns had no server default; the ORM supplied the values.
    for column in ('status_code', 'headers_snippet', 'first_seen_on_page'):
        op.alter_column('findings', column, server_default=None)
    op.drop_index(op.f('ix_findings_evidence_url_id'), table_name='findings')
    op.drop_column('findings', 'evidence_url_id')
