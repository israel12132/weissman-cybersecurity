"""Add assets_json to attack_surface_snapshots for Shadow IT discovery.

Revision ID: 002_assets
Revises: 001_initial
Create Date: 2026-03-12

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "002_assets"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "attack_surface_snapshots",
        sa.Column("assets_json", sa.Text(), server_default="[]", nullable=True),
    )


def downgrade() -> None:
    op.drop_column("attack_surface_snapshots", "assets_json")
