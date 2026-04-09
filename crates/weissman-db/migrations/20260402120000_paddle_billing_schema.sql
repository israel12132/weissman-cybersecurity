-- Migrate SaaS billing schema from Stripe-oriented names to Paddle Billing.
-- Safe for databases that already applied 20260401120000_saas_billing_onboarding.sql.

DO $$
BEGIN
  IF to_regclass('public.tenant_stripe_customers') IS NOT NULL
     AND to_regclass('public.tenant_paddle_customers') IS NULL THEN
    ALTER TABLE tenant_stripe_customers RENAME TO tenant_paddle_customers;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'tenant_paddle_customers' AND column_name = 'stripe_customer_id'
  ) THEN
    ALTER TABLE tenant_paddle_customers RENAME COLUMN stripe_customer_id TO paddle_customer_id;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'tenant_subscriptions' AND column_name = 'stripe_subscription_id'
  ) THEN
    ALTER TABLE tenant_subscriptions RENAME COLUMN stripe_subscription_id TO paddle_subscription_id;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM information_schema.columns
    WHERE table_schema = 'public' AND table_name = 'tenant_subscriptions' AND column_name = 'stripe_price_id'
  ) THEN
    ALTER TABLE tenant_subscriptions RENAME COLUMN stripe_price_id TO paddle_price_id;
  END IF;
END $$;

DO $$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'public' AND c.relname = 'ix_tenant_subscriptions_stripe') THEN
    ALTER INDEX ix_tenant_subscriptions_stripe RENAME TO ix_tenant_subscriptions_paddle;
  END IF;
END $$;

DO $$
BEGIN
  IF to_regclass('public.stripe_webhook_events') IS NOT NULL
     AND to_regclass('public.paddle_webhook_events') IS NULL THEN
    ALTER TABLE stripe_webhook_events RENAME TO paddle_webhook_events;
  END IF;
END $$;

ALTER TABLE billing_plans ADD COLUMN IF NOT EXISTS paddle_price_id TEXT;

CREATE UNIQUE INDEX IF NOT EXISTS uq_billing_plans_paddle_price_id
  ON billing_plans (paddle_price_id)
  WHERE paddle_price_id IS NOT NULL AND trim(paddle_price_id) <> '';

COMMENT ON COLUMN billing_plans.paddle_price_id IS
  'Paddle Billing catalog price ID (pri_...). When set, overrides WEISSMAN_PADDLE_PRICE_* env for that plan slug.';
