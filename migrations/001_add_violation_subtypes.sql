-- Migration: Add new violation subtype columns to analysis table
-- Run with: psql -d xtask -f 001_add_violation_subtypes.sql

ALTER TABLE analysis ADD COLUMN IF NOT EXISTS ssot_leakage_violations BIGINT NOT NULL DEFAULT 0;
ALTER TABLE analysis ADD COLUMN IF NOT EXISTS ssot_cache_violations BIGINT NOT NULL DEFAULT 0;
ALTER TABLE analysis ADD COLUMN IF NOT EXISTS hardcoded_literal_violations BIGINT NOT NULL DEFAULT 0;
ALTER TABLE analysis ADD COLUMN IF NOT EXISTS hardcoded_sleep_violations BIGINT NOT NULL DEFAULT 0;
ALTER TABLE analysis ADD COLUMN IF NOT EXISTS no_cache_violations BIGINT NOT NULL DEFAULT 0;

-- Verify
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'analysis' 
ORDER BY ordinal_position;
