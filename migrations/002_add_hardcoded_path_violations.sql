-- Migration: Add hardcoded_path_violations column to analysis table
-- Run with: psql -d xtask -f 002_add_hardcoded_path_violations.sql

ALTER TABLE analysis ADD COLUMN IF NOT EXISTS hardcoded_path_violations BIGINT NOT NULL DEFAULT 0;

-- Verify
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'analysis'
ORDER BY ordinal_position;

