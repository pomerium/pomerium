---
name: markdown-issue-tracking
description: Use this when creating, updating, triaging, or planning work using the repository's Markdown-based issue files under /.issues.
---

## Canonical issue system
This repo tracks work in /.issues as Markdown files with YAML frontmatter.

## Rules
- One file per issue to avoid merge conflicts.
- Epics are directories under /issues/epics/<epic-name>/ with index.md as the epic overview.
- Always keep frontmatter valid YAML.
- Prefer append-only updates in the Log section to reduce conflicts.

## Status workflow
open -> in_progress -> done
Use blocked only if deps are not done. When unblocked, revert to open.

## Creating an issue
1) Pick a human-readable slug in kebab-case derived from the issue title (e.g., `fix-signal-workflow`, `add-working-hours-utility`).
2) Create file under /issues/inbox or under the relevant epic directory with the slug as filename.
3) Set the `id` field in frontmatter to match the filename (without .md).
4) Add deps using issue slugs.

## Updating
- Update status + updated date.
- Add a log entry describing what changed.
