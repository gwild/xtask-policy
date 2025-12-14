# xtask: Policy Enforcement Agent

This crate provides mechanical enforcement of architectural invariants.

## Status

**In Development** - This will become a git submodule for sharing across repos.

## Usage

```bash
cargo run -p xtask
```

Reads configuration from `policy.toml` in this directory.

## Converting to Submodule

When ready to share:

1. Create a new repo for `xtask`:
   ```bash
   # In a separate location
   git init xtask-policy
   cd xtask-policy
   # Copy contents from focus/xtask
   git add .
   git commit -m "Initial xtask policy enforcement"
   git remote add origin <repo-url>
   git push -u origin main
   ```

2. In this repo, remove `xtask` and add as submodule:
   ```bash
   git rm -r xtask
   git commit -m "Remove xtask, preparing for submodule"
   git submodule add <xtask-repo-url> xtask
   git commit -m "Add xtask as submodule"
   ```

3. In other repos:
   ```bash
   git submodule add <xtask-repo-url> xtask
   ```

## Configuration

Each repo using this submodule should have its own `xtask/policy.toml` customized for its structure.

