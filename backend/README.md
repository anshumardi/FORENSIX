# FORENSIX backend

This is a local-first FastAPI backend for forensic case workspaces. It stores metadata in SQLite, writes uploaded evidence and generated PDF reports into private managed directories, exposes only controlled download routes, and protects API resources with local bcrypt authentication and roles.

## Run locally

```bash
cd /home/anshu/FORENSIX/backend
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The first startup seeds one clearly labeled `[DEMO]` case, synthetic evidence, a timeline event, a custody event, and a synthetic finding. Set `FORENSIX_SEED_DEMO=false` to disable it. Data defaults to `backend/data/`. The first browser visit creates the administrator; no default password is created.

Useful environment variables:

| Variable | Purpose |
| --- | --- |
| `FORENSIX_DATA_DIR` | Root for the default SQLite database, evidence, and reports directories |
| `FORENSIX_DATABASE` | Explicit SQLite path |
| `FORENSIX_EVIDENCE_DIR` | Explicit private evidence directory |
| `FORENSIX_REPORTS_DIR` | Explicit private report directory |
| `FORENSIX_MAX_UPLOAD_BYTES` | Maximum streamed evidence payload; default 100 MiB |
| `FORENSIX_SEED_DEMO` | Enable or disable the demo seed; default `true` |
| `FORENSIX_TSHARK_BIN` / `FORENSIX_SLEUTHKIT_BIN` / `FORENSIX_VOLATILITY_BIN` | Optional executable paths |

Optional tools are discovered with `PATH` or their explicit environment variable. Actions are allowlisted (`version` and a fixed `probe`) and run as argument lists with shell execution disabled.

Evidence ingestion calculates MD5, SHA-1, and SHA-256, stores the managed file with mode `0444`, and records an initial custody handoff. Audit events include a user ID, previous hash, and entry hash. `GET /api/audit-events/verify` checks the chain and returns the first broken entry when tampering is detected. Reviewers authenticate successfully but are rejected from write-shaped API actions.

## Background worker

Analysis requests are inserted into SQLite as `queued` jobs. Run the separate worker from this directory:

```bash
python worker.py
```

The worker claims one job at a time, executes only registered adapters, bounds output/logs, honors cancellation checkpoints, and records `running`, `succeeded`, or `failed` state. The API does not execute heavy adapter parsing inline.

Registered local adapters include TShark PCAP metadata, IOC extraction, EVTX timeline parsing, file triage, and YARA scanning. Adapter results that create IOCs or timeline events include source evidence ID, parser name/version, and observation timestamp provenance. Triage and YARA results remain in bounded job output.

Phase 4 investigator endpoints include FTS5 `/api/search`, Markdown note storage at `/api/notes`, and bounded read-only `/api/evidence/{id}/hex` ranges. Generated PDFs support executive/technical templates and detached Ed25519 signatures. Verify one with:

```bash
python verify_report.py report.pdf --signature report.pdf.sig --public-key data/keys/ed25519-public.pem
```

Run tests from this directory with:

```bash
pytest
```
