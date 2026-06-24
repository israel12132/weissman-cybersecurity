# Git & Credential Security

## Rotate exposed GitHub token (if remote URL contains `ghp_` or `github_pat_`)

1. GitHub → Settings → Developer settings → Personal access tokens → **Revoke** the exposed token.
2. Switch remote to SSH (recommended):

```bash
git remote set-url origin git@github.com:israel12132/weissman-cybersecurity.git
ssh -T git@github.com
git push origin main
```

Or use GitHub CLI: `gh auth login` then HTTPS without embedding tokens in URL.

## Never commit

- `.env` with real secrets
- `deploy/company.details.json` with real ח.פ. (use `.example` only in repo)

## Pre-push checklist

```bash
./scripts/go_live_check.sh
git diff --stat
# ensure no .env in staging area
git status
```
