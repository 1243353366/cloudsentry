# CloudSentry vendor notice

This directory vendors selected source material from [HuginnsHammer/CloudSentry](https://github.com/HuginnsHammer/CloudSentry) for an optional, local-only configuration-audit integration.

- **Upstream repository:** `https://github.com/HuginnsHammer/CloudSentry.git`
- **Reviewed upstream commit:** `0e4fd3b55fcb4073db6943e4a2ad802b5e0dba6c`
- **Upstream commit date:** `2026-10-28T23:16:41+03:00`
- **Source retrieved for this vendor copy:** `2026-10-30`
- **License:** MIT; the unmodified upstream license is retained in [`LICENSE`](LICENSE).
- **Upstream copyright:** Copyright (c) 2026 HuginnsHammer.

The copied `scanner/`, `frontend/`, `docs/`, `tests/`, `examples/`, upstream project metadata, and supporting upstream documents retain their original upstream content and copyright notices. This is a source snapshot only: it contains no `.git` history, binaries, virtual environments, `node_modules`, package installation output, or real `.env` file. `.env.example` is retained because it is a non-secret example.

Integration-specific files in this directory are `NOTICE.md` and `bridge_runner.py`. Host-side authorization and the fixed subprocess bridge live outside this vendor snapshot. The integration intentionally does not start the upstream FastAPI service or frontend.
