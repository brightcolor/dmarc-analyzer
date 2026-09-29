"""senders with names: sender of each source and decisions per sender

Revision ID: 0004
Revises: 0003
Create Date: 2026-09-29 14:40:00

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0004'
down_revision: str | None = '0003'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'sender_approvals',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('sender_key', sa.String(length=64), nullable=False),
        sa.Column('classification', sa.String(length=20), nullable=False),
        sa.Column('decided_by', sa.String(length=36), nullable=True),
        sa.Column('decided_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['decided_by'], ['users.id'], ondelete='SET NULL'),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('organization_id', 'sender_key', name='uq_sender_approval_org_key'),
    )
    op.create_index(op.f('ix_sender_approvals_organization_id'), 'sender_approvals', ['organization_id'])

    op.add_column('source_ips', sa.Column('classification_source', sa.String(length=20), nullable=True))
    op.add_column('source_ips', sa.Column('reverse_dns_confirmed', sa.Boolean(), nullable=True))
    op.add_column('source_ips', sa.Column('sender_key', sa.String(length=64), nullable=True))
    op.add_column('source_ips', sa.Column('sender_evidence', sa.String(length=300), nullable=True))
    op.create_index(op.f('ix_source_ips_sender_key'), 'source_ips', ['sender_key'])

    # Every classification so far was set by a person
    op.execute("UPDATE source_ips SET classification_source = 'manual' WHERE classification <> 'unknown'")


def downgrade() -> None:
    op.drop_index(op.f('ix_source_ips_sender_key'), table_name='source_ips')
    op.drop_column('source_ips', 'sender_evidence')
    op.drop_column('source_ips', 'sender_key')
    op.drop_column('source_ips', 'reverse_dns_confirmed')
    op.drop_column('source_ips', 'classification_source')
    op.drop_index(op.f('ix_sender_approvals_organization_id'), table_name='sender_approvals')
    op.drop_table('sender_approvals')
