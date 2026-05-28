# DMARC Analyzer

A self-hosted, multi-tenant DMARC aggregate report analyzer.
Receives reports by email (custom SMTP inbound), processes them against RFC 7489, and presents pass/fail breakdowns, source IP classification, and actionable recommendations through a web UI and REST API.

---

## Features

- **SMTP Inbound** — slim custom server (aiosmtpd); never relays; rejects unknown/disabled recipients at `RCPT TO`
- **DMARC evaluation** — RFC 7489: SPF/DKIM alignment, relaxed/strict, `sp=`, `pct=`, policy enforcement
- **XXE protection** — all XML parsed with `defusedxml`
- **Zip/gzip bomb protection** — incremental extraction with 50 MB limit
- **Multi-tenant** — every query scoped by `organization_id`; no cross-tenant data leakage
- **Rule-based recommendations** — 10 actionable rules, no AI/ML required
- **Alert rules** — configurable with cooldown; notifies via webhook, ntfy, or Slack
- **REST API** — Bearer token auth; key endpoints for reports, domains, source IPs
- **Admin UI** — AdminLTE 4 / Bootstrap 5 server-side rendered (Jinja2)
- **Docker Compose** — web + SMTP + PostgreSQL; ready for a 1–2 vCPU vServer

---

## Quickstart (Docker Compose)

```bash
git clone https://github.com/brightcolor/dmarc-analyzer.git && cd dmarc-analyzer && cp .env.example .env && docker compose up -d
```

Open **http://localhost:8765** — the setup wizard runs on first visit and lets you create the admin account directly in the browser. No environment variables required for the first run.

For production, edit `.env` before starting: set `POSTGRES_PASSWORD`, `SECRET_KEY`, and `SMTP_INBOUND_DOMAIN` to your actual mail domain.

---

## DNS / MX setup

Point an MX record at the host running the SMTP inbound service.

```
reports.yourdomain.example.com.  MX 10  your-server-ip-or-hostname.
```

Then configure your DMARC record to deliver reports to inbound addresses
created inside the application (Settings → Organizations → Inbound Addresses).

Example DMARC RUA tag:
```
v=DMARC1; p=none; rua=mailto:org-myorg-abc123@reports.yourdomain.example.com
```

---

## Local development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env   # edit as needed

# SQLite works out-of-the-box for local dev:
# DATABASE_URL=sqlite:///./dmarc.db

alembic upgrade head
uvicorn app.main:app --reload --port 8765
```

Open **http://localhost:8765** — the setup wizard appears on first visit.

In a second terminal:
```bash
python -m smtp_inbound
```

---

## Running tests

```bash
make test          # runs pytest with in-memory SQLite — no external services needed
make cov           # includes HTML coverage report in htmlcov/
make lint          # ruff checks
```

---

## API

All API routes live under `/api/v1/`. Authentication uses a Bearer token:

```bash
curl -H "Authorization: Bearer <token>" http://localhost:8765/api/v1/me
```

Generate a token in the web UI under **API Tokens**.

Key endpoints:

| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/v1/health` | Health check (unauthenticated) |
| GET | `/api/v1/version` | Application version |
| GET | `/api/v1/me` | Current authenticated user |
| GET | `/api/v1/domains` | List domains for the current org |
| GET | `/api/v1/reports` | List DMARC reports (paginated) |
| GET | `/api/v1/reports/{id}` | Report detail with records |
| GET | `/api/v1/source-ips` | Source IP list |
| GET | `/api/v1/alerts/events` | Open alert events |
| GET | `/api/v1/inbound-addresses` | Inbound addresses |
| GET | `/api/v1/smtp/status` | SMTP server status (superadmin) |

---

## Configuration reference

All settings are loaded from environment variables (or a `.env` file).
See [`.env.example`](.env.example) for the full list with descriptions.

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `SECRET_KEY` | Yes | — | Session signing key (64 hex chars) |
| `DATABASE_URL` | Yes | — | SQLAlchemy database URL |
| `SMTP_INBOUND_DOMAIN` | Yes | — | Domain for inbound addresses |
| `POSTGRES_PASSWORD` | Yes (compose) | — | PostgreSQL password |
| `INITIAL_ADMIN_EMAIL` | No | — | Bootstrap admin account on first start |
| `INITIAL_ADMIN_PASSWORD` | No | — | Bootstrap admin password |
| `SMTP_INBOUND_PORT` | No | `2525` | SMTP listen port |
| `SMTP_IP_RATE_LIMIT` | No | `60` | Max connections per IP per hour |
| `MAX_UPLOAD_SIZE_MB` | No | `25` | Upload file size limit |

---

## Security

See [SECURITY.md](SECURITY.md) for the vulnerability reporting policy and security design notes.

---

## Backup & restore

### PostgreSQL (Docker Compose)

```bash
# Backup
docker compose exec db pg_dump -U dmarc dmarc > backup.sql

# Restore
docker compose exec -T db psql -U dmarc dmarc < backup.sql
```

### Uploaded files

Copy the bind-mount directories on the host:

```bash
cp -r ./data/uploads ./data/raw_mail /your/backup/location/
```

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

---

## License

[MIT](LICENSE)
