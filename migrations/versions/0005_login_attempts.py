"""login attempts for the lock against guessing

Revision ID: 0005
Revises: 0004
Create Date: 2026-09-29 15:10:00

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = '0005'
down_revision: str | None = '0004'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        'login_attempts',
        sa.Column('id', sa.String(length=36), nullable=False),
        sa.Column('kind', sa.String(length=20), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=False),
        sa.Column('account', sa.String(length=255), nullable=True),
        sa.Column('success', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint('id'),
    )
    op.create_index(op.f('ix_login_attempts_ip_address'), 'login_attempts', ['ip_address'])
    op.create_index(op.f('ix_login_attempts_account'), 'login_attempts', ['account'])
    op.create_index(op.f('ix_login_attempts_created_at'), 'login_attempts', ['created_at'])


def downgrade() -> None:
    op.drop_index(op.f('ix_login_attempts_created_at'), table_name='login_attempts')
    op.drop_index(op.f('ix_login_attempts_account'), table_name='login_attempts')
    op.drop_index(op.f('ix_login_attempts_ip_address'), table_name='login_attempts')
    op.drop_table('login_attempts')
