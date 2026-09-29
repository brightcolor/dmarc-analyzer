"""failure reports (ruf)

Revision ID: 0006
Revises: 0005
Create Date: 2026-09-29 17:30:00

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0006'
down_revision: str | None = '0005'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

INDEXED = ('organization_id', 'domain_id', 'smtp_message_id', 'reported_domain', 'source_ip', 'created_at')


def upgrade() -> None:
    op.create_table(
        'dmarc_failure_reports',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('domain_id', sa.String(length=36), nullable=True),
        sa.Column('smtp_message_id', sa.String(length=36), nullable=True),
        sa.Column('import_source', sa.String(length=30), nullable=False),
        sa.Column('reporter', sa.String(length=500), nullable=True),
        sa.Column('user_agent', sa.String(length=255), nullable=True),
        sa.Column('reporting_mta', sa.String(length=255), nullable=True),
        sa.Column('feedback_type', sa.String(length=50), nullable=True),
        sa.Column('auth_failure', sa.String(length=100), nullable=True),
        sa.Column('identity_alignment', sa.String(length=50), nullable=True),
        sa.Column('delivery_result', sa.String(length=50), nullable=True),
        sa.Column('reported_domain', sa.String(length=255), nullable=True),
        sa.Column('source_ip', sa.String(length=45), nullable=True),
        sa.Column('arrival_date', sa.DateTime(timezone=True), nullable=True),
        sa.Column('incidents', sa.Integer(), nullable=False),
        sa.Column('original_mail_from', sa.String(length=320), nullable=True),
        sa.Column('original_rcpt_to', sa.String(length=1000), nullable=True),
        sa.Column('dkim_domain', sa.String(length=255), nullable=True),
        sa.Column('dkim_identity', sa.String(length=320), nullable=True),
        sa.Column('dkim_selector', sa.String(length=255), nullable=True),
        sa.Column('spf_dns', sa.String(length=500), nullable=True),
        sa.Column('authentication_results', sa.Text(), nullable=True),
        sa.Column('header_from', sa.String(length=500), nullable=True),
        sa.Column('subject', sa.String(length=500), nullable=True),
        sa.Column('message_id', sa.String(length=500), nullable=True),
        sa.Column('original_headers', sa.Text(), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['smtp_message_id'], ['smtp_inbound_messages.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
    )
    for column in INDEXED:
        op.create_index(op.f(f'ix_dmarc_failure_reports_{column}'), 'dmarc_failure_reports', [column])


def downgrade() -> None:
    for column in reversed(INDEXED):
        op.drop_index(op.f(f'ix_dmarc_failure_reports_{column}'), table_name='dmarc_failure_reports')
    op.drop_table('dmarc_failure_reports')
