# xtask_plot

Interactive time-series plotting GUI for `xtask analyze` metrics stored in Postgres table `analysis`.

## Requirements

- `analysis` table exists (see `xtask/analysis_schema.sql`)
- Environment variable **`XTASK_ANALYSIS_DB_URL`** is set (typically via `.env`)

Example:

```bash
export XTASK_ANALYSIS_DB_URL='postgres://USER:PASS@HOST:5432/xtask'
```

## Run

You can run from **repo root** (recommended):

```bash
set -a && source .env && set +a && cargo run -p xtask_plot
```

Or if you are in the `xtask/` directory (like your terminal example), source the parent `.env`:

```bash
set -a && source ../.env && set +a && cargo run -p xtask_plot
```

Or if you are in `xtask/xtask_plot/`:

```bash
set -a && source ../../.env && set +a && cargo run -p xtask_plot
```

## UI

- Left panel is an **interactive legend**:
  - Click a metric label to **mute/unmute** that series
  - “Unmute all” restores all series
- Top controls:
  - Range (hours)
  - Refresh


