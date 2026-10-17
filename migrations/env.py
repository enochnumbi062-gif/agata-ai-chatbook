"""Environnement Alembic : réutilise le moteur et les modèles de main.py (une seule source de vérité)."""
import sys
from logging.config import fileConfig
from pathlib import Path

from alembic import context

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import main  # noqa: E402  (DATABASE_URL normalisée, moteur et modèles SQLAlchemy)

config = context.config
if config.config_file_name and not config.attributes.get("skip_logging"):
    fileConfig(config.config_file_name, disable_existing_loggers=False)

target_metadata = main.Base.metadata


def run_migrations_offline() -> None:
    """Génère le SQL sans se connecter : alembic upgrade head --sql"""
    context.configure(url=main.DATABASE_URL, target_metadata=target_metadata, literal_binds=True,
                      dialect_opts={"paramstyle": "named"}, render_as_batch=main.IS_SQLITE)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    with main.engine.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata,
                          render_as_batch=main.IS_SQLITE,  # SQLite : ALTER TABLE limité → mode batch
                          compare_type=True)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
