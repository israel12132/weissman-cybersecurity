#!/bin/bash
# בודק אם משתמש admin נוצר במסד הנתונים

echo "=== בודק משתמש admin במסד נתונים ==="
docker compose exec postgres psql -U postgres -d weissman -c "
SELECT
    id,
    email,
    role,
    is_superadmin,
    is_active,
    created_at
FROM users
WHERE email = 'admin@localhost' OR lower(email) LIKE '%admin%'
ORDER BY created_at DESC;
"

echo ""
echo "=== כל המשתמשים במערכת ==="
docker compose exec postgres psql -U postgres -d weissman -c "
SELECT
    id,
    email,
    role,
    is_superadmin,
    is_active
FROM users
ORDER BY id;
"
