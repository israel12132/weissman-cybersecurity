-- Billing usage snapshot (pre-aggregated) + 15s analytics SLA.
--
-- weissman_analytics must not run live aggregation over raw meter tables
-- (millions of quota/LLM rows). The worker refreshes this snapshot via a
-- SECURITY DEFINER function; billing reads one PK row.

ALTER ROLE weissman_analytics SET statement_timeout = '15s';

CREATE TABLE IF NOT EXISTS public.weissman_billing_usage_snapshot (
    tenant_id        BIGINT NOT NULL REFERENCES public.tenants (id) ON DELETE CASCADE,
    period_ym        TEXT NOT NULL,
    scans_started    BIGINT NOT NULL DEFAULT 0,
    quota_used_json  JSONB NOT NULL DEFAULT '{}'::jsonb,
    llm_tokens       BIGINT NOT NULL DEFAULT 0,
    refreshed_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (tenant_id, period_ym)
);

COMMENT ON TABLE public.weissman_billing_usage_snapshot IS
    'Pre-aggregated per-tenant billing meters. Refreshed asynchronously; API reads one PK row.';

CREATE INDEX IF NOT EXISTS ix_tenant_llm_usage_created_at
    ON public.tenant_llm_usage (created_at);

ALTER TABLE public.weissman_billing_usage_snapshot ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.weissman_billing_usage_snapshot FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS weissman_billing_usage_snapshot_tenant ON public.weissman_billing_usage_snapshot;
CREATE POLICY weissman_billing_usage_snapshot_tenant ON public.weissman_billing_usage_snapshot
    FOR ALL
    USING (tenant_id = public.app_current_tenant_id())
    WITH CHECK (tenant_id = public.app_current_tenant_id());

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_app') THEN
        GRANT SELECT ON public.weissman_billing_usage_snapshot TO weissman_app;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_analytics') THEN
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'billing_plans' AND relnamespace = 'public'::regnamespace) THEN
            GRANT SELECT ON public.billing_plans TO weissman_analytics;
        END IF;
        GRANT SELECT ON public.weissman_billing_usage_snapshot TO weissman_analytics;
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'tenant_usage_counters' AND relnamespace = 'public'::regnamespace) THEN
            REVOKE SELECT ON public.tenant_usage_counters FROM weissman_analytics;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'weissman_tenant_quota_usage' AND relnamespace = 'public'::regnamespace) THEN
            REVOKE SELECT ON public.weissman_tenant_quota_usage FROM weissman_analytics;
        END IF;
        IF EXISTS (SELECT 1 FROM pg_class WHERE relname = 'tenant_llm_usage' AND relnamespace = 'public'::regnamespace) THEN
            REVOKE SELECT ON public.tenant_llm_usage FROM weissman_analytics;
        END IF;
    END IF;
END
$$;

CREATE OR REPLACE FUNCTION public.weissman_refresh_billing_usage_snapshot()
RETURNS bigint
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, public
SET default_transaction_read_only = off
SET row_security = off
SET statement_timeout = '15s'
AS $fn$
DECLARE
    n bigint := 0;
    p text;
BEGIN
    p := to_char((now() AT TIME ZONE 'UTC'), 'YYYY-MM');
    INSERT INTO public.weissman_billing_usage_snapshot (
        tenant_id, period_ym, scans_started, quota_used_json, llm_tokens, refreshed_at
    )
    SELECT
        t.tenant_id,
        p,
        COALESCE(c.scans_started, 0),
        COALESCE(q.quota_used_json, '{}'::jsonb),
        COALESCE(l.llm_tokens, 0),
        now()
    FROM (
        SELECT DISTINCT tenant_id FROM (
            SELECT tenant_id FROM public.tenant_usage_counters WHERE period_ym = p
            UNION
            SELECT tenant_id FROM public.weissman_tenant_quota_usage WHERE period_key = p
            UNION
            SELECT tenant_id FROM public.tenant_llm_usage
            WHERE created_at >= date_trunc('month', timezone('UTC', now()))
              AND created_at < date_trunc('month', timezone('UTC', now())) + interval '1 month'
        ) u
    ) t
    LEFT JOIN public.tenant_usage_counters c
      ON c.tenant_id = t.tenant_id AND c.period_ym = p
    LEFT JOIN LATERAL (
        SELECT COALESCE(jsonb_object_agg(resource, used), '{}'::jsonb) AS quota_used_json
        FROM public.weissman_tenant_quota_usage u
        WHERE u.tenant_id = t.tenant_id AND u.period_key = p
    ) q ON true
    LEFT JOIN LATERAL (
        SELECT COALESCE(SUM(total_tokens), 0)::bigint AS llm_tokens
        FROM public.tenant_llm_usage lu
        WHERE lu.tenant_id = t.tenant_id
          AND lu.created_at >= date_trunc('month', timezone('UTC', now()))
          AND lu.created_at < date_trunc('month', timezone('UTC', now())) + interval '1 month'
    ) l ON true
    ON CONFLICT (tenant_id, period_ym) DO UPDATE SET
        scans_started = EXCLUDED.scans_started,
        quota_used_json = EXCLUDED.quota_used_json,
        llm_tokens = EXCLUDED.llm_tokens,
        refreshed_at = EXCLUDED.refreshed_at;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n;
END;
$fn$;

COMMENT ON FUNCTION public.weissman_refresh_billing_usage_snapshot() IS
    'Owner-definer upsert of weissman_billing_usage_snapshot for the current UTC month. '
    'Called by weissman_worker; not on the billing request path.';

REVOKE ALL ON FUNCTION public.weissman_refresh_billing_usage_snapshot() FROM PUBLIC;

DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'weissman_worker') THEN
        GRANT EXECUTE ON FUNCTION public.weissman_refresh_billing_usage_snapshot() TO weissman_worker;
    END IF;
END
$$;
