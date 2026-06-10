-- Run as PostgreSQL superuser after migrations (20260608140300_nl_query_readonly_role).
-- Sets a production password for the Ask Weissman read-only role.
--
--   psql -U postgres -d weissman -v ro_password="'$(openssl rand -base64 24)'" -f deploy/grant-postgres-weissman-ro.sql
--
-- Then set WEISSMAN_READ_ONLY_DATABASE_URL to:
--   postgresql://weissman_ro:<password>@<host>:5432/weissman?sslmode=require

\if :{?ro_password}
ALTER ROLE weissman_ro WITH LOGIN PASSWORD :'ro_password';
\else
\echo 'Set ro_password, e.g.: psql ... -v ro_password="'"'"'your-strong-secret'"'"'" -f deploy/grant-postgres-weissman-ro.sql'
\endif
