"""further recipients per domain for alerts and the weekly digest

Revision ID: 0007
Revises: 0006
Create Date: 2026-09-29 18:00:00

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0007'
down_revision: str | None = '0006'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'domain_recipients',
        sa.Column('id', sa.String(), nullable=False),
        sa.Column('organization_id', sa.String(length=36), nullable=False),
        sa.Column('domain_id', sa.String(length=36), nullable=False),
        sa.Column('email', sa.String(length=320), nullable=False),
        sa.Column('name', sa.String(length=200), nullable=True),
        sa.Column('alerts', sa.Boolean(), nullable=False),
        sa.Column('digest', sa.Boolean(), nullable=False),
        sa.Column('digest_last_sent_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ondelete='CASCADE'),
        sa.ForeignKeyConstraint(['domain_id'], ['domains.id'], ondelete='CASCADE'),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('domain_id', 'email', name='uq_domain_recipients_domain_email'),
    )
    op.create_index(op.f('ix_domain_recipients_organization_id'), 'domain_recipients', ['organization_id'])
    op.create_index(op.f('ix_domain_recipients_domain_id'), 'domain_recipients', ['domain_id'])

    # A delivery goes to a channel or to a single address
    with op.batch_alter_table('notification_deliveries') as batch:
        batch.alter_column('channel_id', existing_type=sa.String(length=36), nullable=True)
        batch.add_column(sa.Column('recipient', sa.String(length=320), nullable=True))


def downgrade() -> None:
    op.execute("DELETE FROM notification_deliveries WHERE channel_id IS NULL")
    with op.batch_alter_table('notification_deliveries') as batch:
        batch.drop_column('recipient')
        batch.alter_column('channel_id', existing_type=sa.String(length=36), nullable=False)
    op.drop_index(op.f('ix_domain_recipients_domain_id'), table_name='domain_recipients')
    op.drop_index(op.f('ix_domain_recipients_organization_id'), table_name='domain_recipients')
    op.drop_table('domain_recipients')
