-- Pre-auth demo/contact leads from the public flagship site.
-- Not tenant-scoped: the visitor has no tenant yet. weissman_app inserts from
-- POST /api/public/contact; there is no public SELECT.
CREATE TABLE IF NOT EXISTS public.public_contact_leads (
  id            bigserial PRIMARY KEY,
  created_at    timestamptz NOT NULL DEFAULT now(),
  name          text        NOT NULL,
  email         text        NOT NULL,
  company       text,
  message       text        NOT NULL,
  source        text,
  client_ip     text
);

CREATE INDEX IF NOT EXISTS public_contact_leads_created_at_idx
  ON public.public_contact_leads (created_at DESC);

GRANT SELECT, INSERT ON public.public_contact_leads TO weissman_app;
GRANT USAGE, SELECT ON SEQUENCE public.public_contact_leads_id_seq TO weissman_app;
