"""scheduler runs, weekly digest and notification retries

Revision ID: 0003
Revises: 0002
Create Date: 2026-09-29 13:29:58.754871

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0003'
down_revision: str | None = '0002'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'scheduler_runs',
        sa.Column('name', sa.String(length=50), nullable=False),
        sa.Column('last_started_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_finished_at', sa.DateTime(timezone=True), nullable=True),
        sa.Column('last_status', sa.String(length=20), nullable=True),
        sa.Column('last_error', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('name'),
    )
    op.add_column('organizations', sa.Column('digest_enabled', sa.Boolean(), server_default=sa.true(), nullable=False))
    op.add_column('organizations', sa.Column('digest_recipients', sa.Text(), nullable=True))
    op.add_column('organizations', sa.Column('digest_last_sent_at', sa.DateTime(timezone=True), nullable=True))
    op.add_column(
        'notification_deliveries', sa.Column('next_attempt_at', sa.DateTime(timezone=True), nullable=True)
    )


def downgrade() -> None:
    op.drop_column('notification_deliveries', 'next_attempt_at')
    op.drop_column('organizations', 'digest_last_sent_at')
    op.drop_column('organizations', 'digest_recipients')
    op.drop_column('organizations', 'digest_enabled')
    op.drop_table('scheduler_runs')
