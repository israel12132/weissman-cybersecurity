"""Initial schema for Weissman-cybersecurity (PostgreSQL).

Revision ID: 001
Revises:
Create Date: 2026-03-12

"""
from typing import Sequence, Union
from alembic import op
import sqlalchemy as sa

revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "clients",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("name", sa.String(255), nullable=False),
        sa.Column("domains", sa.Text(), default="[]"),
        sa.Column("ip_ranges", sa.Text(), default="[]"),
        sa.Column("tech_stack", sa.Text(), default="[]"),
        sa.Column("contact_email", sa.String(255), default=""),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=True),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("now()"), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "report_runs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=True),
        sa.Column("findings_json", sa.Text(), default="[]"),
        sa.Column("summary", sa.Text(), default="{}"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_report_runs_created_at", "report_runs", ["created_at"], unique=False)
    op.create_table(
        "webhooks",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("url", sa.String(2048), nullable=False),
        sa.Column("enabled", sa.Integer(), default=1),
        sa.Column("secret", sa.String(512), default=""),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_table(
        "alert_sent",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("target", sa.String(512), nullable=False),
        sa.Column("finding_id", sa.String(512), nullable=False),
        sa.Column("alerted_at", sa.DateTime(), server_default=sa.text("now()"), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_alert_sent_alerted_at", "alert_sent", ["alerted_at"], unique=False)
    op.create_index("ix_alert_sent_target_finding", "alert_sent", ["target", "finding_id"], unique=False)
    op.create_index("ix_alert_sent_target_alerted_at", "alert_sent", ["target", "alerted_at"], unique=False)
    op.create_index("ix_alert_sent_target", "alert_sent", ["target"], unique=False)
    op.create_index("ix_alert_sent_finding_id", "alert_sent", ["finding_id"], unique=False)

    op.create_table(
        "users",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(255), nullable=False),
        sa.Column("role", sa.String(64), nullable=False, server_default="viewer"),
        sa.Column("mfa_secret", sa.String(64), default=""),
        sa.Column("mfa_enabled", sa.Boolean(), default=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=True),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("now()"), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_users_email", "users", ["email"], unique=True)

    op.create_table(
        "system_audit_logs",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("created_at", sa.DateTime(), server_default=sa.text("now()"), nullable=True),
        sa.Column("user_id", sa.Integer(), nullable=True),
        sa.Column("user_email", sa.String(255), default=""),
        sa.Column("action", sa.String(128), nullable=False),
        sa.Column("ip_address", sa.String(64), default=""),
        sa.Column("details", sa.Text(), default="{}"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_created_at", "system_audit_logs", ["created_at"], unique=False)
    op.create_index("ix_audit_user_id", "system_audit_logs", ["user_id"], unique=False)
    op.create_index("ix_audit_action", "system_audit_logs", ["action"], unique=False)

    op.create_table(
        "attack_surface_snapshots",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("target_id", sa.String(128), nullable=False),
        sa.Column("target_type", sa.String(32), default="client"),
        sa.Column("ports_json", sa.Text(), default="[]"),
        sa.Column("headers_hash", sa.String(64), default=""),
        sa.Column("cve_ids_json", sa.Text(), default="[]"),
        sa.Column("updated_at", sa.DateTime(), server_default=sa.text("now()"), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_snapshot_target", "attack_surface_snapshots", ["target_id"], unique=False)


def downgrade() -> None:
    op.drop_index("ix_snapshot_target", "attack_surface_snapshots")
    op.drop_table("attack_surface_snapshots")
    op.drop_index("ix_audit_action", "system_audit_logs")
    op.drop_index("ix_audit_user_id", "system_audit_logs")
    op.drop_index("ix_audit_created_at", "system_audit_logs")
    op.drop_table("system_audit_logs")
    op.drop_index("ix_users_email", "users")
    op.drop_table("users")
    op.drop_index("ix_alert_sent_finding_id", "alert_sent")
    op.drop_index("ix_alert_sent_target", "alert_sent")
    op.drop_index("ix_alert_sent_target_alerted_at", "alert_sent")
    op.drop_index("ix_alert_sent_target_finding", "alert_sent")
    op.drop_index("ix_alert_sent_alerted_at", "alert_sent")
    op.drop_table("alert_sent")
    op.drop_table("webhooks")
    op.drop_index("ix_report_runs_created_at", "report_runs")
    op.drop_table("report_runs")
    op.drop_table("clients")
