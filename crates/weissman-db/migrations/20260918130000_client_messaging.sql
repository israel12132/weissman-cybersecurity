-- Per-client internal messaging + help board, and per-user / per-client images.
--
-- Messaging: every employee attached to a client shares ONE message board for
-- that client. A message never leaves its client — visibility is walled by the
-- same app.current_client_id RLS as every other client-scoped table, so a
-- portal/below-admin user only ever sees their own client's board and staff /
-- owner (unscoped) can read every board (useful for answering `help` requests).
--
-- `kind='help'` is an ordinary board message flagged as a help request so the
-- MSSP staff/owner can spot and answer it.
--
-- Images: users.avatar_url and clients.logo_url hold a small image reference —
-- either an https URL or an inline `data:image/...;base64,...` URL (size-capped
-- by the API). No object storage is required.

CREATE TABLE IF NOT EXISTS client_messages (
    id               BIGSERIAL PRIMARY KEY,
    tenant_id        BIGINT NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    client_id        BIGINT NOT NULL REFERENCES clients(id) ON DELETE CASCADE,
    sender_user_id   BIGINT REFERENCES users(id) ON DELETE SET NULL,
    sender_email     TEXT NOT NULL DEFAULT '',
    kind             TEXT NOT NULL DEFAULT 'message'
        CHECK (kind IN ('message', 'help')),
    body             TEXT NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Board read: newest last is built in the API; this index serves "latest N for a
-- client" and stays tight as history grows.
CREATE INDEX IF NOT EXISTS ix_client_messages_client_created
    ON client_messages (tenant_id, client_id, created_at DESC);

-- Open help requests across a tenant (staff/owner triage).
CREATE INDEX IF NOT EXISTS ix_client_messages_help
    ON client_messages (tenant_id, created_at DESC)
    WHERE kind = 'help';

ALTER TABLE client_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_messages FORCE ROW LEVEL SECURITY;

-- Tenant wall AND per-client wall: a scoped session (app.current_client_id set)
-- only sees its own client's rows; an unscoped staff/owner session sees the
-- whole tenant. Mirrors the pattern every client-scoped table uses.
DROP POLICY IF EXISTS client_messages_scope ON client_messages;
CREATE POLICY client_messages_scope ON client_messages FOR ALL
    USING (
        tenant_id = public.app_current_tenant_id()
        AND public.weissman_client_row_visible(client_id)
    )
    WITH CHECK (
        tenant_id = public.app_current_tenant_id()
        AND public.weissman_client_row_visible(client_id)
    );

GRANT SELECT, INSERT, UPDATE, DELETE ON client_messages TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE client_messages_id_seq TO weissman_app;

-- Per-user avatar and per-client logo (URL or inline data: URL; API caps size).
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar_url TEXT NOT NULL DEFAULT '';
ALTER TABLE clients ADD COLUMN IF NOT EXISTS logo_url TEXT NOT NULL DEFAULT '';

COMMENT ON COLUMN users.avatar_url IS
    'Optional profile image for the user (https URL or inline data:image URL, size-capped by the API).';
COMMENT ON COLUMN clients.logo_url IS
    'Optional logo/image for the client workspace (https URL or inline data:image URL, size-capped by the API).';
