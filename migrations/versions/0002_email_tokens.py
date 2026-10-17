"""Jetons e-mail : vérification d'adresse et réinitialisation du mot de passe.

Révision : 0002_email_tokens
Précédente : 0001_baseline
"""
import sqlalchemy as sa
from alembic import op

revision = "0002_email_tokens"
down_revision = "0001_baseline"
branch_labels = None
depends_on = None


def upgrade() -> None:
    if "email_tokens" in sa.inspect(op.get_bind()).get_table_names():
        return
    op.create_table(
        "email_tokens",
        sa.Column("id", sa.Integer, primary_key=True),
        sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("purpose", sa.String(16), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("ix_email_tokens_user_id", "email_tokens", ["user_id"])
    op.create_index("ix_email_tokens_token_hash", "email_tokens", ["token_hash"], unique=True)


def downgrade() -> None:
    op.drop_index("ix_email_tokens_token_hash", table_name="email_tokens")
    op.drop_index("ix_email_tokens_user_id", table_name="email_tokens")
    op.drop_table("email_tokens")
