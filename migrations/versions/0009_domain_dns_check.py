"""DNS check per domain

Revision ID: 0009
Revises: 0008
Create Date: 2026-09-30 09:00:00

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0009'
down_revision: str | None = '0008'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.add_column('domains', sa.Column('dns_status', sa.String(length=20), nullable=True))
    op.add_column('domains', sa.Column('dns_checked_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column('domains', sa.Column('dns_results', sa.Text(), nullable=True))
    op.create_index(op.f('ix_domains_dns_status'), 'domains', ['dns_status'])
    op.create_index(op.f('ix_domains_dns_checked_at'), 'domains', ['dns_checked_at'])


def downgrade() -> None:
    op.drop_index(op.f('ix_domains_dns_checked_at'), table_name='domains')
    op.drop_index(op.f('ix_domains_dns_status'), table_name='domains')
    op.drop_column('domains', 'dns_results')
    op.drop_column('domains', 'dns_checked_at')
    op.drop_column('domains', 'dns_status')
