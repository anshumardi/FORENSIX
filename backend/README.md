# FORENSIX backend

This is a local-first FastAPI backend for forensic case workspaces. It stores metadata in SQLite, writes uploaded evidence and generated PDF reports into private managed directories, and exposes only controlled download routes.

## Run locally

```bash
cd /home/anshu/FORENSIX/backend
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

The first startup seeds one clearly labeled `[DEMO]` case, synthetic evidence, a timeline event, and a synthetic finding. Set `FORENSIX_SEED_DEMO=false` to disable it. Data defaults to `backend/data/`.

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

Run tests from this directory with:

```bash
pytest
```
