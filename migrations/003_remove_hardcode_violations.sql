-- Migration: Remove generic hardcode_violations column
-- All hardcodes are now categorized (hardcoded_path_violations, hardcoded_literal_violations, hardcoded_sleep_violations)

ALTER TABLE analysis DROP COLUMN IF EXISTS hardcode_violations;
