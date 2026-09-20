-- Step 5 (least privilege): move WRITES to the global ioc_feed_credentials secrets
-- table behind a SECURITY DEFINER function, so the runtime app role can no longer
-- perform arbitrary DML on the platform's encrypted feed credentials.
--
-- ioc_feed_credentials holds AES-256-GCM envelopes of the platform's IOC feed API
-- keys (abuse.ch / OTX / MISP). Before this migration weissman_app held full
-- INSERT/UPDATE/DELETE on it (20260917120000_ioc_feed_credentials.sql), so any code
-- path — or a future SQL-injection sink — running as the app role could mass-DELETE
-- the secrets, forge updated_by / updated_at, or write keys outside the intended
-- upsert shape. The only legitimate writer is the admin-gated PUT /api/ioc/credentials
-- handler (fingerprint_engine/src/ioc/creds.rs::set), which performs one narrow upsert
-- (and already gates the key against a whitelist in Rust).
--
-- Constrain the DB-level write surface to exactly that upsert: a SECURITY DEFINER
-- function owned by the migration role (which owns the table), executable only by
-- weissman_app. now() is always server-derived, so updated_at cannot be forged, and
-- there is no DELETE path (clearing a credential is an upsert to value_enc=''). SELECT
-- stays granted — refresh_from_db reads the table on the app pool.

CREATE OR REPLACE FUNCTION public.set_ioc_feed_credential(
    p_key        TEXT,
    p_value_enc  TEXT,
    p_updated_by TEXT
) RETURNS void
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF p_key IS NULL OR btrim(p_key) = '' THEN
        RAISE EXCEPTION 'set_ioc_feed_credential: key must be non-empty';
    END IF;
    INSERT INTO public.ioc_feed_credentials (key, value_enc, updated_by, updated_at)
    VALUES (p_key, COALESCE(p_value_enc, ''), COALESCE(p_updated_by, ''), now())
    ON CONFLICT (key) DO UPDATE SET
        value_enc  = EXCLUDED.value_enc,
        updated_by = EXCLUDED.updated_by,
        updated_at = now();
END;
$$;

-- SECURITY DEFINER functions are created with EXECUTE granted to PUBLIC by default;
-- revoke that first, then grant only the app role.
REVOKE ALL ON FUNCTION public.set_ioc_feed_credential(TEXT, TEXT, TEXT) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION public.set_ioc_feed_credential(TEXT, TEXT, TEXT) TO weissman_app;

-- Remove the app role's arbitrary write on the secrets table; keep SELECT for the
-- process-cache refresh. Writes now flow only through the constrained definer function.
-- (Idempotent: REVOKE of an absent privilege is a no-op.)
REVOKE INSERT, UPDATE, DELETE ON public.ioc_feed_credentials FROM weissman_app;
