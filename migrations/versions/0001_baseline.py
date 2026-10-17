"""Schéma de base (idempotent).

Fonctionne sur les trois situations possibles :
  1. base vide                       → crée toutes les tables ;
  2. base créée par l'ancienne version (create_all, colonne posts.created, sans active/label…)
                                     → renomme et ajoute les colonnes manquantes ;
  3. base créée par la v2 (ensure_schema) → ne change rien.

Révision : 0001_baseline
"""
import sqlalchemy as sa
from alembic import op

revision = "0001_baseline"
down_revision = None
branch_labels = None
depends_on = None

TS = sa.DateTime(timezone=True)


def _tables() -> set[str]:
    return set(sa.inspect(op.get_bind()).get_table_names())


def _columns(table: str) -> set[str]:
    return {c["name"] for c in sa.inspect(op.get_bind()).get_columns(table)}


def upgrade() -> None:
    tables = _tables()
    if "users" not in tables:
        op.create_table(
            "users",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("email", sa.String(255), nullable=False),
            sa.Column("pw", sa.String(255), nullable=False),
            sa.Column("role", sa.String(10), nullable=False, server_default="user"),
            sa.Column("credits", sa.Integer, nullable=False, server_default="20"),
            sa.Column("active", sa.Boolean, nullable=False, server_default=sa.true()),
            sa.Column("email_verified", sa.Boolean, nullable=False, server_default=sa.false()),
            sa.Column("token_version", sa.Integer, nullable=False, server_default="0"),
            sa.Column("created_at", TS, nullable=True),
        )
        op.create_index("ix_users_email", "users", ["email"], unique=True)
    if "api_keys" not in tables:
        op.create_table(
            "api_keys",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("provider", sa.String(20), nullable=False),
            sa.Column("label", sa.String(60), nullable=False, server_default=""),
            sa.Column("blob", sa.Text, nullable=False),
            sa.UniqueConstraint("user_id", "provider", name="uq_user_provider"),
        )
        op.create_index("ix_api_keys_user_id", "api_keys", ["user_id"])
    if "posts" not in tables:
        op.create_table(
            "posts",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("kind", sa.String(10), nullable=False),
            sa.Column("title", sa.String(200), nullable=False),
            sa.Column("body", sa.Text, nullable=False),
            sa.Column("status", sa.String(12), nullable=False, server_default="pending"),
            sa.Column("reason", sa.String(300), nullable=False, server_default=""),
            sa.Column("votes", sa.Integer, nullable=False, server_default="0"),
            sa.Column("created_at", TS, nullable=True),
        )
        op.create_index("ix_posts_user_id", "posts", ["user_id"])
        op.create_index("ix_posts_status", "posts", ["status"])
    if "votes" not in tables:
        op.create_table(
            "votes",
            sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), primary_key=True),
            sa.Column("post_id", sa.Integer, sa.ForeignKey("posts.id", ondelete="CASCADE"), primary_key=True),
        )
    if "passkeys" not in tables:
        op.create_table(
            "passkeys",
            sa.Column("id", sa.Integer, primary_key=True),
            sa.Column("user_id", sa.Integer, sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
            sa.Column("cred_id", sa.String(1024), nullable=False, unique=True),
            sa.Column("pub", sa.Text, nullable=False),
            sa.Column("count", sa.Integer, nullable=False, server_default="0"),
            sa.Column("label", sa.String(80), nullable=False, server_default=""),
        )
        op.create_index("ix_passkeys_user_id", "passkeys", ["user_id"])

    # --- Mise à niveau des bases créées par les anciennes versions ---
    post_cols = _columns("posts")
    if "created" in post_cols and "created_at" not in post_cols:
        op.execute("ALTER TABLE posts RENAME COLUMN created TO created_at")
    elif "created_at" not in post_cols:
        op.add_column("posts", sa.Column("created_at", TS, nullable=True))
    additions = {
        "users": [
            sa.Column("active", sa.Boolean, nullable=False, server_default=sa.true()),
            sa.Column("email_verified", sa.Boolean, nullable=False, server_default=sa.false()),
            sa.Column("token_version", sa.Integer, nullable=False, server_default="0"),
            sa.Column("created_at", TS, nullable=True),
        ],
        "passkeys": [sa.Column("label", sa.String(80), nullable=False, server_default="")],
    }
    for table, columns in additions.items():
        existing = _columns(table)
        for column in columns:
            if column.name not in existing:
                op.add_column(table, column)


def downgrade() -> None:
    for table in ("votes", "passkeys", "api_keys", "posts", "users"):
        op.drop_table(table)
