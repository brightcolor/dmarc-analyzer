"""SMTP TLS reports (TLS-RPT, RFC 8460)

Revision ID: 0008
Revises: 0007
Create Date: 2026-09-29 21:30:00

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0008'
down_revision: str | None = '0007'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

INDEXED = {
    'tls_reports': ('organization_id', 'domain_id', 'smtp_message_id', 'period_begin', 'policy_domain', 'created_at'),
    'tls_report_policies': ('report_id',),
    'tls_report_failures': ('policy_id', 'result_type'),
}


def upgrade() -> None:
    op.create_table(
        'tls_reports',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('domain_id', sa.String(length=36), nullable=True),
        sa.Column('smtp_message_id', sa.String(length=36), nullable=True),
        sa.Column('import_source', sa.String(length=30), nullable=False),
        sa.Column('report_id', sa.String(length=500), nullable=False),
        sa.Column('organization_name', sa.String(length=500), nullable=True),
        sa.Column('contact_info', sa.String(length=500), nullable=True),
        sa.Column('period_begin', sa.DateTime(timezone=True), nullable=True),
        sa.Column('period_end', sa.DateTime(timezone=True), nullable=True),
        sa.Column('policy_domain', sa.String(length=255), nullable=True),
        sa.Column('successful_sessions', sa.Integer(), nullable=False),
        sa.Column('failed_sessions', sa.Integer(), nullable=False),
        sa.Column('failure_details_omitted', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['smtp_message_id'], ['smtp_inbound_messages.id'], ondelete='SET NULL'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('organization_id', 'report_id', name='uq_tls_reports_org_report'),
    )
    op.create_table(
        'tls_report_policies',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('report_id', sa.String(length=36), nullable=False),
        sa.Column('position', sa.Integer(), nullable=False),
        sa.Column('policy_type', sa.String(length=30), nullable=False),
        sa.Column('policy_domain', sa.String(length=255), nullable=True),
        sa.Column('policy_strings', sa.Text(), nullable=True),
        sa.Column('mx_hosts', sa.Text(), nullable=True),
        sa.Column('successful_sessions', sa.Integer(), nullable=False),
        sa.Column('failed_sessions', sa.Integer(), nullable=False),
        sa.ForeignKeyConstraint(['report_id'], ['tls_reports.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_table(
        'tls_report_failures',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('policy_id', sa.String(length=36), nullable=False),
        sa.Column('result_type', sa.String(length=60), nullable=False),
        sa.Column('sending_mta_ip', sa.String(length=45), nullable=True),
        sa.Column('receiving_mx_hostname', sa.String(length=255), nullable=True),
        sa.Column('receiving_mx_helo', sa.String(length=255), nullable=True),
        sa.Column('receiving_ip', sa.String(length=45), nullable=True),
        sa.Column('failed_sessions', sa.Integer(), nullable=False),
        sa.Column('additional_information', sa.String(length=1000), nullable=True),
        sa.Column('failure_reason_code', sa.String(length=255), nullable=True),
        sa.ForeignKeyConstraint(['policy_id'], ['tls_report_policies.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
    )
    for table, columns in INDEXED.items():
        for column in columns:
            op.create_index(op.f(f'ix_{table}_{column}'), table, [column])


def downgrade() -> None:
    for table, columns in reversed(INDEXED.items()):
        for column in reversed(columns):
            op.drop_index(op.f(f'ix_{table}_{column}'), table_name=table)
        op.drop_table(table)
