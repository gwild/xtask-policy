-- Run this on the Postgres server (as a role with permission to create DB/tables).
-- Creates database `xtask` and table `analysis` for logging `xtask analyze` runs.

CREATE DATABASE xtask;

\c xtask

CREATE TABLE analysis (
  id BIGSERIAL PRIMARY KEY,
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

  host TEXT NOT NULL,
  xtask_version TEXT NOT NULL,

  scan_root TEXT NOT NULL,
  policy_path TEXT NOT NULL,
  policy_sha256 TEXT NOT NULL,

  output_arg TEXT NOT NULL,
  output_path TEXT NOT NULL,
  output_sha256 TEXT NOT NULL,

  total_violations BIGINT NOT NULL,
  lock_violations BIGINT NOT NULL,
  spawn_violations BIGINT NOT NULL,
  ssot_violations BIGINT NOT NULL,
  ssot_leakage_violations BIGINT NOT NULL DEFAULT 0,
  ssot_cache_violations BIGINT NOT NULL DEFAULT 0,
  fallback_violations BIGINT NOT NULL,
  required_config_violations BIGINT NOT NULL,
  sensitive_violations BIGINT NOT NULL,
  hardcoded_path_violations BIGINT NOT NULL DEFAULT 0,
  hardcoded_literal_violations BIGINT NOT NULL DEFAULT 0,
  hardcoded_sleep_violations BIGINT NOT NULL DEFAULT 0,
  style_violations BIGINT NOT NULL,
  blocking_lock_violations BIGINT NOT NULL,
  no_cache_violations BIGINT NOT NULL DEFAULT 0,
  files_affected BIGINT NOT NULL,

  hotspot_1 TEXT NULL,
  hotspot_2 TEXT NULL,
  hotspot_3 TEXT NULL,
  hotspot_4 TEXT NULL,
  hotspot_5 TEXT NULL,

  report_md TEXT NOT NULL,
  payload_json JSONB NOT NULL
);

CREATE INDEX analysis_recorded_at_idx ON analysis (recorded_at DESC);
CREATE INDEX analysis_total_violations_idx ON analysis (total_violations DESC);


