-- Live AWS canary: OAST correlation URL stored alongside deception asset (EventBridge + OOB).
ALTER TABLE deception_assets
    ADD COLUMN IF NOT EXISTS oast_canary_hook TEXT NOT NULL DEFAULT '';
