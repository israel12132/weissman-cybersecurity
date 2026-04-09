"""Multi-tenancy: tenants table and client.tenant_id.

Revision ID: 003
Revises: 002_assets
Create Date: 2026-03-12

"""
from alembic import op
import sqlalchemy as sa


revision = "003"
down_revision = "002_assets"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("slug", sa.String(64), nullable=False),
        sa.Column("settings_json", sa.Text(), server_default="{}"),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("now()")),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_tenants_slug", "tenants", ["slug"], unique=True)
    op.add_column("clients", sa.Column("tenant_id", sa.Integer(), nullable=True))
    op.create_index("ix_clients_tenant_id", "clients", ["tenant_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_clients_tenant_id", "clients")
    op.drop_column("clients", "tenant_id")
    op.drop_index("ix_tenants_slug", "tenants")
    op.drop_table("tenants")
