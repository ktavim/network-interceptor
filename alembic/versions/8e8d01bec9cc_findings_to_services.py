"""findings to services

A findings row is one external service a scan saw (an origin and its
authentication), not an issue, and the crawler already called it one. Renames
the table, urls.finding_id, and every constraint and index named after them,
so a migrated database matches one built fresh from the models. Metadata
only: no rows are rewritten.

Revision ID: 8e8d01bec9cc
Revises: c7e2a9d41f06
Create Date: 2026-09-28 01:37:43.362325

"""
from typing import Sequence, Union

from alembic import op


# revision identifiers, used by Alembic.
revision: str = '8e8d01bec9cc'
down_revision: Union[str, Sequence[str], None] = 'c7e2a9d41f06'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# (table as named after the upgrade, old name, new name). Postgres keeps
# these names across a table or column rename; the pkey and unique
# constraint rename their backing indexes with them.
_CONSTRAINTS = [
    ('services', 'findings_pkey', 'services_pkey'),
    ('services', 'findings_scan_id_fkey', 'services_scan_id_fkey'),
    ('services', 'uq_findings_scan_origin', 'uq_services_scan_origin'),
    ('services', 'fk_findings_evidence_url_id', 'fk_services_evidence_url_id'),
    ('urls', 'urls_finding_id_fkey', 'urls_service_id_fkey'),
]
_INDEXES = [
    ('ix_findings_scan_id', 'ix_services_scan_id'),
    ('ix_findings_evidence_url_id', 'ix_services_evidence_url_id'),
    ('ix_urls_finding_id', 'ix_urls_service_id'),
]


def upgrade() -> None:
    """Upgrade schema."""
    op.rename_table('findings', 'services')
    op.alter_column('urls', 'finding_id', new_column_name='service_id')
    for table, old, new in _CONSTRAINTS:
        op.execute(f'ALTER TABLE {table} RENAME CONSTRAINT {old} TO {new}')
    for old, new in _INDEXES:
        op.execute(f'ALTER INDEX {old} RENAME TO {new}')


def downgrade() -> None:
    """Downgrade schema."""
    for old, new in _INDEXES:
        op.execute(f'ALTER INDEX {new} RENAME TO {old}')
    for table, old, new in _CONSTRAINTS:
        op.execute(f'ALTER TABLE {table} RENAME CONSTRAINT {new} TO {old}')
    op.alter_column('urls', 'service_id', new_column_name='finding_id')
    op.rename_table('services', 'findings')
