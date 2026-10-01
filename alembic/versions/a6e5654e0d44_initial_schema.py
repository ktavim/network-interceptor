"""initial schema

The schema of the merged service, which runs two scanners (interceptor and
tracer) per scan. It starts on a fresh database: this revision replaces the
history that led to the interceptor-only schema, and no data is carried over.

A scan's work is one scan_jobs row per scanner, and that table is the job
queue. A services row is one origin per scan, combined across the scanners;
service_findings keeps each scanner's own verdict for it, and urls holds the
evidence rows of both.

Revision ID: a6e5654e0d44
Revises:
Create Date: 2026-10-01 21:29:45.836838

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = 'a6e5654e0d44'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

# The vocabularies of core.enums as they stand at this revision. Each column
# holding one is a plain string with a CHECK, so adding a value later is a
# migration that drops and re-adds that column's constraint.
_AUTH_METHODS = (
    "('ntlm', 'kerberos', 'negotiate', 'oauth', 'login_redirect', 'basic', 'bearer', "
    "'api_key', 'other', 'unauthenticated', 'no_response', 'dns_failed', 'unknown')"
)
_SEVERITIES = "('blocker', 'review', 'cleared')"
_SCANNERS = "('interceptor', 'tracer')"
_SCAN_STATUSES = "('queued', 'running', 'completed', 'partial', 'failed', 'cancelled')"
_JOB_STATUSES = "('queued', 'running', 'completed', 'failed', 'cancelled')"


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('apps',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('url', sa.String(), nullable=True),
    sa.Column('owner_ad_group', sa.String(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('current_scan_id', sa.String(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('scans',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('app_id', sa.String(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('url', sa.String(), nullable=False),
    sa.Column('status', sa.String(), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('started_by', sa.String(), nullable=False),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('cancel_requested_at', sa.DateTime(timezone=True), nullable=True),
    sa.CheckConstraint(f"status IN {_SCAN_STATUSES}", name='ck_scans_status'),
    sa.ForeignKeyConstraint(['app_id'], ['apps.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_scans_app_id'), 'scans', ['app_id'], unique=False)
    op.create_index(op.f('ix_scans_status'), 'scans', ['status'], unique=False)
    # apps <-> scans is a circular FK. Autogenerate renders this side inline in
    # create_table('apps') with use_alter=True, which op.create_table silently
    # skips on PostgreSQL -- so add it explicitly now that scans exists.
    op.create_foreign_key(
        'fk_apps_current_scan_id', 'apps', 'scans',
        ['current_scan_id'], ['id'], ondelete='SET NULL',
    )
    op.create_table('scan_events',
    sa.Column('scan_id', sa.String(), nullable=False),
    sa.Column('seq', sa.Integer(), nullable=False),
    sa.Column('ts', sa.BigInteger(), nullable=False),
    sa.Column('type', sa.String(), nullable=False),
    sa.Column('payload', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('scan_id', 'seq')
    )
    op.create_table('scan_jobs',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('scan_id', sa.String(), nullable=False),
    sa.Column('scanner', sa.String(), nullable=False),
    sa.Column('status', sa.String(), nullable=False),
    sa.Column('settings', postgresql.JSONB(astext_type=sa.Text()), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('worker_id', sa.String(), nullable=True),
    sa.Column('heartbeat_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('error', sa.Text(), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('started_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('completed_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('pages_crawled', sa.Integer(), nullable=True),
    sa.CheckConstraint(f"scanner IN {_SCANNERS}", name='ck_scan_jobs_scanner'),
    sa.CheckConstraint(f"status IN {_JOB_STATUSES}", name='ck_scan_jobs_status'),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('scan_id', 'scanner', name='uq_scan_jobs_scan_scanner')
    )
    op.create_index('ix_scan_jobs_claim', 'scan_jobs', ['scanner', 'status', 'created_at'], unique=False)
    op.create_table('services',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('scan_id', sa.String(), nullable=False),
    sa.Column('scheme', sa.String(), nullable=False),
    sa.Column('host', sa.String(), nullable=False),
    sa.Column('port', sa.Integer(), nullable=False),
    sa.Column('auth_method', sa.String(), nullable=False),
    sa.Column('severity', sa.String(), nullable=False),
    sa.Column('request_count', sa.Integer(), nullable=False),
    sa.Column('ips', postgresql.ARRAY(sa.String()), nullable=True),
    sa.Column('evidence_url_id', sa.String(), nullable=True),
    sa.Column('excluded', sa.Boolean(), nullable=False),
    sa.CheckConstraint(f"auth_method IN {_AUTH_METHODS}", name='ck_services_auth_method'),
    sa.CheckConstraint(f"severity IN {_SEVERITIES}", name='ck_services_severity'),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('scan_id', 'scheme', 'host', 'port', name='uq_services_scan_origin')
    )
    op.create_index(op.f('ix_services_evidence_url_id'), 'services', ['evidence_url_id'], unique=False)
    op.create_index(op.f('ix_services_scan_id'), 'services', ['scan_id'], unique=False)
    op.create_table('submissions',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('scan_id', sa.String(), nullable=False),
    sa.Column('submitted_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('submitted_by', sa.String(), nullable=False),
    sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('scan_id', name='uq_submissions_scan_id')
    )
    op.create_index(op.f('ix_submissions_scan_id'), 'submissions', ['scan_id'], unique=False)
    op.create_table('urls',
    sa.Column('id', sa.String(), nullable=False),
    sa.Column('service_id', sa.String(), nullable=False),
    sa.Column('scanner', sa.String(), nullable=False),
    sa.Column('method', sa.String(), nullable=False),
    sa.Column('url', sa.String(), nullable=False),
    sa.Column('resource_type', sa.String(), nullable=False),
    sa.Column('status_code', sa.Integer(), nullable=False),
    sa.Column('failure_reason', sa.String(), nullable=True),
    sa.Column('auth_method', sa.String(), nullable=False),
    sa.Column('sent_auth_scheme', sa.String(), nullable=True),
    sa.Column('auth_challenge', sa.Text(), nullable=True),
    sa.Column('redirect_url', sa.String(), nullable=True),
    sa.Column('page_url', sa.String(), nullable=False),
    sa.Column('sources', postgresql.ARRAY(sa.Text()), server_default=sa.text("'{}'"), nullable=False),
    sa.CheckConstraint(f"auth_method IN {_AUTH_METHODS}", name='ck_urls_auth_method'),
    sa.CheckConstraint(f"scanner IN {_SCANNERS}", name='ck_urls_scanner'),
    sa.ForeignKeyConstraint(['service_id'], ['services.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_urls_service_id'), 'urls', ['service_id'], unique=False)
    # services -> urls -> services is the other cycle, skipped by
    # op.create_table for the same reason. Deferred so a scan's services can
    # be inserted ahead of the url rows they point to within one transaction.
    op.create_foreign_key(
        'fk_services_evidence_url_id', 'services', 'urls',
        ['evidence_url_id'], ['id'], ondelete='SET NULL',
        deferrable=True, initially='DEFERRED',
    )
    # No cycle here: service_findings is created after both tables it
    # references, so its deferred evidence key goes inline.
    op.create_table('service_findings',
    sa.Column('service_id', sa.String(), nullable=False),
    sa.Column('scanner', sa.String(), nullable=False),
    sa.Column('auth_method', sa.String(), nullable=False),
    sa.Column('evidence_url_id', sa.String(), nullable=True),
    sa.Column('url_count', sa.Integer(), nullable=False),
    sa.CheckConstraint(f"auth_method IN {_AUTH_METHODS}", name='ck_service_findings_auth_method'),
    sa.CheckConstraint(f"scanner IN {_SCANNERS}", name='ck_service_findings_scanner'),
    sa.ForeignKeyConstraint(['evidence_url_id'], ['urls.id'], name='fk_service_findings_evidence_url_id', ondelete='SET NULL', initially='DEFERRED', deferrable=True),
    sa.ForeignKeyConstraint(['service_id'], ['services.id'], ondelete='CASCADE'),
    sa.PrimaryKeyConstraint('service_id', 'scanner')
    )
    op.create_index(op.f('ix_service_findings_evidence_url_id'), 'service_findings', ['evidence_url_id'], unique=False)


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_service_findings_evidence_url_id'), table_name='service_findings')
    op.drop_table('service_findings')
    # Break the services <-> urls cycle first, or drop_table('urls') fails.
    op.drop_constraint('fk_services_evidence_url_id', 'services', type_='foreignkey')
    op.drop_index(op.f('ix_urls_service_id'), table_name='urls')
    op.drop_table('urls')
    op.drop_index(op.f('ix_submissions_scan_id'), table_name='submissions')
    op.drop_table('submissions')
    op.drop_index(op.f('ix_services_scan_id'), table_name='services')
    op.drop_index(op.f('ix_services_evidence_url_id'), table_name='services')
    op.drop_table('services')
    op.drop_index('ix_scan_jobs_claim', table_name='scan_jobs')
    op.drop_table('scan_jobs')
    op.drop_table('scan_events')
    # Break the apps <-> scans cycle first, or drop_table('scans') fails.
    op.drop_constraint('fk_apps_current_scan_id', 'apps', type_='foreignkey')
    op.drop_index(op.f('ix_scans_status'), table_name='scans')
    op.drop_index(op.f('ix_scans_app_id'), table_name='scans')
    op.drop_table('scans')
    op.drop_table('apps')
