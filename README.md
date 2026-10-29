# FORENSIX

FORENSIX is a local-first digital-forensics investigation workspace for evidence the operator owns or is authorized to examine. It combines a Next.js App Router console with a separate FastAPI service, SQLite metadata, private evidence storage, SHA-256 integrity checks, transparent relationships, timeline and finding records, optional forensic-tool adapters, and ReportLab PDF reports.

> **Authorization and education notice:** analyze only evidence you are authorized to examine. FORENSIX is an educational aid and case-work management tool, not a substitute for validated forensic procedures, laboratory controls, legal advice, or expert testimony. Matching hashes support post-acquisition integrity checking; they do not independently prove authenticity or correct acquisition.

## Stack and non-negotiable frontend choice

- Frontend: Next.js App Router, React, TypeScript, `next dev`, `next build`, and `next start`.
- Backend: Python, FastAPI, Pydantic, Uvicorn.
- Database: SQLite. Large evidence objects and generated PDFs remain on local disk outside the frontend public directory.
- Reports: ReportLab PDF generation.
- Optional adapters: TShark, The Sleuth Kit, and Volatility 3 are detected at runtime and never assumed to be installed.
- **No Vite:** there is no Vite dependency, script, or configuration in this project.

## Project tree

```text
FORENSIX/
├── README.md
├── .gitignore
├── backend/
│   ├── requirements.txt
│   ├── README.md
│   ├── app/
│   │   ├── main.py          # FastAPI routes and application lifecycle
│   │   ├── database.py      # SQLite schema, migrations, connections
│   │   ├── schemas.py       # Pydantic API contracts
│   │   ├── storage.py       # bounded uploads, hashes, safe previews
│   │   ├── reports.py       # private ReportLab output
│   │   ├── integrations.py  # optional-tool discovery and fixed probes
│   │   ├── audit.py         # append-only audit records
│   │   └── seed.py          # clearly labeled synthetic demo data
│   └── tests/
│       ├── conftest.py
│       └── test_api.py
└── frontend/
    ├── package.json         # Next.js scripts; no Vite
    ├── next.config.mjs
    ├── app/
    │   ├── page.tsx         # overview dashboard
    │   ├── cases/            # registry and case workspace
    │   ├── evidence/         # inventory and safe details/preview
    │   ├── timeline/
    │   ├── network/
    │   ├── graph/
    │   ├── findings/
    │   ├── reports/
    │   ├── integrations/
    │   ├── settings/
    │   └── help/
    └── .env.example
```

## Prerequisites

- Linux/macOS/WSL or another environment that supports Node.js and Python.
- Node.js 18.18+ (Node 24 was used for the verified build) and npm.
- Python 3.11+ with a working `venv`/pip installation. Python 3.14 was used for the verified backend tests.
- Optional: `tshark`, The Sleuth Kit (`mmls`/`fls`), and Volatility 3.

## Installation and launch on the current Linux workspace

Open two terminals from the extracted `FORENSIX` directory.

### 1. Install backend dependencies

The current image does not ship `ensurepip`, so the exact verified setup uses a venv without pip and pip's `--python` target option. On a normal Python installation, the standard `python3 -m venv .venv && .venv/bin/python -m pip ...` flow is equivalent.

```bash
cd /home/anshu/FORENSIX
python3 -m venv --without-pip .venv
python3 -m pip --python /home/anshu/FORENSIX/.venv install -r backend/requirements.txt
```

If `python3 -m pip` is unavailable on another machine, install the operating system's Python venv/pip package first (for example, `python3-venv` and `python3-pip` on Debian/Ubuntu). Do not place uploaded evidence or credentials in the repository.

### 2. Start the backend

```bash
cd /home/anshu/FORENSIX/backend
/home/anshu/FORENSIX/.venv/bin/uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Backend URLs:

- Health: http://127.0.0.1:8000/health
- OpenAPI/Swagger: http://127.0.0.1:8000/docs
- ReDoc: http://127.0.0.1:8000/redoc

### 3. Install and start the frontend

```bash
cd /home/anshu/FORENSIX/frontend
npm install
npm run dev
```

Frontend URL: http://localhost:3000

For a production frontend:

```bash
cd /home/anshu/FORENSIX/frontend
npm run build
npm run start
```

The browser client defaults to `http://127.0.0.1:8000`. To override it, copy `.env.example` to `.env.local` and set `NEXT_PUBLIC_API_URL`. The backend CORS default allows only local Next.js origins; change `FORENSIX_CORS_ORIGINS` only when the local deployment requires it.

## Backend configuration

The backend defaults to `backend/data/`, which is private and ignored by git. Useful environment variables:

| Variable | Default | Purpose |
| --- | --- | --- |
| `FORENSIX_DATA_DIR` | `backend/data` | Root for SQLite, evidence, and reports |
| `FORENSIX_DATABASE` | `${FORENSIX_DATA_DIR}/forensix.sqlite3` | Explicit database path |
| `FORENSIX_EVIDENCE_DIR` | `${FORENSIX_DATA_DIR}/evidence` | Private evidence directory |
| `FORENSIX_REPORTS_DIR` | `${FORENSIX_DATA_DIR}/reports` | Private PDF directory |
| `FORENSIX_MAX_UPLOAD_BYTES` | `104857600` | Streamed upload limit (100 MiB) |
| `FORENSIX_SEED_DEMO` | `true` | Seed one synthetic `[DEMO]` case on first startup |
| `FORENSIX_CORS_ORIGINS` | localhost/127.0.0.1:3000 | Comma-separated local origins |
| `FORENSIX_COMMAND_TIMEOUT_SECONDS` | `20` | Optional-tool subprocess timeout |
| `FORENSIX_TSHARK_BIN` | PATH lookup | Explicit TShark executable |
| `FORENSIX_SLEUTHKIT_BIN` | PATH lookup | Explicit Sleuth Kit executable |
| `FORENSIX_VOLATILITY_BIN` | PATH lookup | Explicit Volatility executable |

The demo case and file are synthetic training data, clearly labeled as not real evidence. Disable it for a clean workspace with `FORENSIX_SEED_DEMO=false` before first startup.

## Implemented workflow

1. **Cases:** create, list, open, and update case title, description, status, severity, assignee, and tags. Each mutation is recorded in the audit table.
2. **Evidence:** upload a local file to a generated private filename. Client paths are rejected, size is enforced while streaming, duplicate content in the same case is reported as HTTP 409, and uploads are never executed.
3. **Integrity:** SHA-256 is calculated during ingestion. The evidence view can recalculate it, store a verification history record, and show match/mismatch/unavailable status.
4. **Safe preview:** only bounded UTF-8 text and JSON can be previewed. HTML, scripts, binary content, and untrusted markup are not rendered.
5. **Timeline:** create timezone-aware normalized events, optionally link an evidence record, mark an uncertain timestamp, attach raw JSON metadata, search, filter by case, and sort chronologically.
6. **Findings:** record analyst-created findings with severity, confidence, interpretation notes, and explicit evidence references.
7. **Graph/network:** graph data is derived from explicit case, timeline, and finding/evidence references. Edges include a basis/provenance; the UI does not infer a person from an IP or claim attribution.
8. **Reports:** generate a private PDF for one case or all cases containing case details, evidence hashes, findings, timeline, detected tool versions, audit entries, report ID, and limitations. Full evidence contents are not embedded by default.
9. **Optional tooling:** the integrations view reports actual availability. Fixed argument lists, `shell=False`, timeouts, and bounded output are used for optional probes. Missing tools leave the rest of the workspace usable.

## Demo workflow

1. Start both services and open http://localhost:3000.
2. Open **Cases** and select the `[DEMO] Suspicious workstation activity` case.
3. Open its evidence item, run **Verify integrity**, and view the recorded check history.
4. Use **Safe preview** on the synthetic text file; no script or HTML is rendered.
5. Add a timeline event and an investigator finding from the case workspace.
6. Open **Graph** to inspect explicit case/evidence/finding relationships and their methodology.
7. Open **Reports**, choose the demo case ID, and generate/download a PDF.
8. Open **Integrations** to see whether TShark, The Sleuth Kit, or Volatility 3 are installed on the host.

## Security and privacy behavior

- Development servers bind to localhost by default.
- Evidence and reports are not mounted as public frontend assets; only controlled API download routes can return them.
- Uploaded names are validated and generated storage names prevent overwrites and traversal.
- Uploads are hashed and written as bytes; no uploaded binary, script, or memory content is executed.
- Optional subprocess calls use fixed argument lists, `shell=False`, timeouts, and output bounds.
- Evidence is processed locally by default. There is no AI or external evidence-upload integration.
- The audit log is append-only within SQLite through update/delete triggers, but it is not a cryptographically tamper-evident log and should not be represented as one.

## Tests and checks

Backend tests (verified in the current workspace):

```bash
cd /home/anshu/FORENSIX/backend
/home/anshu/FORENSIX/.venv/bin/python -m pytest -q
# 5 passed
```

Frontend production build (verified in the current workspace):

```bash
cd /home/anshu/FORENSIX/frontend
npm install
npm run build
# Next.js production compilation, TypeScript validation, and all 14 routes generated
```

Additional static checks:

```bash
cd /home/anshu/FORENSIX
/home/anshu/FORENSIX/.venv/bin/python -m compileall -q backend/app backend/tests
! find frontend backend -type f \( -name '*vite*' -o -name 'vite.config.*' \) -print
```

There is intentionally no Vite package or configuration. The frontend scripts are exactly `next dev`, `next build`, and `next start`.

## Optional forensic tools and limitations

- **TShark:** install the platform package (`tshark`) to enable packet-capture tool status and fixed probes. A capture is not decrypted by FORENSIX, and unsupported/invalid captures return an actionable tool error.
- **The Sleuth Kit:** install the platform package containing `mmls`/`fls` to enable disk-tool status and controlled probe support. Original disk images are not modified; full filesystem interpretation is intentionally not claimed by this initial version.
- **Volatility 3:** install Volatility 3 and configure `FORENSIX_VOLATILITY_BIN` when the command is not named `vol` or `vol.py`. Plugin output is bounded and time-limited; the application does not execute code found in memory dumps.
- Network and graph pages show only records returned by the local API. Empty data is displayed honestly; the application does not fabricate packet metadata, relationships, timestamps, or attribution.
- Authentication, multi-user authorization, encrypted at-rest storage, signed/tamper-evident audit logs, and courtroom validation controls are outside this educational initial version.

## Troubleshooting

- **Frontend says API unavailable:** confirm the backend is listening on `127.0.0.1:8000`, open `/health`, and check `NEXT_PUBLIC_API_URL`.
- **Upload returns 413:** raise `FORENSIX_MAX_UPLOAD_BYTES` deliberately, or use a smaller test fixture. The check is enforced while streaming.
- **Upload returns 409:** the same SHA-256 and byte size are already recorded for that case. Review the existing item instead of creating a duplicate.
- **Preview returns 415:** only UTF-8 text/JSON with supported text extensions or media types can be previewed. Download the object for controlled offline review instead.
- **PDF generation fails:** check `GET /health` for ReportLab availability and reinstall `backend/requirements.txt` in the active environment.
- **Optional tool unavailable:** use Integrations for the exact status message and configure the corresponding environment variable after installation.

## API reference

FastAPI publishes the live OpenAPI contract at http://127.0.0.1:8000/docs. Important routes include:

```text
GET    /api/cases
POST   /api/cases
GET    /api/cases/{id}
PATCH  /api/cases/{id}
GET    /api/evidence
POST   /api/evidence
GET    /api/evidence/{id}/preview
POST   /api/evidence/{id}/verify
GET    /api/evidence/{id}/verification-history
GET/POST /api/timeline
GET/POST /api/findings
GET/POST /api/reports
GET    /api/integrations
POST   /api/integrations/{id}/actions
GET    /api/analysis-jobs
GET    /api/graph
GET    /api/network
GET    /api/audit-events
```
