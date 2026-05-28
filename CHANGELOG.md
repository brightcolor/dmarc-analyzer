# Changelog

All notable changes to DMARC Analyzer are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versioning follows [SemVer](https://semver.org/).

---

## [Unreleased]

## [0.1.0] – 2026-05-28

### Added

#### Core
- Multi-tenant organization model with membership roles (`org_admin`, `member`, `viewer`)
- Every database query scoped by `organization_id` — no cross-tenant data leakage
- Plan definitions with per-org feature limits (SaaS-ready, billing not yet wired)

#### DMARC Processing
- RFC 7489-compliant DMARC evaluation (SPF/DKIM alignment, relaxed/strict, `sp=`, `pct=`)
- XXE-safe XML parser via `defusedxml` — external entity attacks blocked
- ZIP bomb protection: incremental extraction with size limit (50 MB uncompressed)
- Gzip bomb protection: streamed decompression with size limit
- ZIP path-traversal protection: entries with `..` or absolute paths are skipped
- Maximum records per report enforced (50 000) to prevent memory exhaustion
- Duplicate report detection: same `report_id` × org is idempotent

#### SMTP Inbound
- Custom slim SMTP server using `aiosmtpd` — no relay, no forwarding
- `RCPT TO` validated before `DATA` is accepted
- Unknown recipient → `550 5.1.1 Recipient unknown`
- Disabled/revoked recipient → `550 5.1.1 Recipient disabled`
- Inactive organisation → `550 5.7.1 Organization disabled`
- Per-IP and per-recipient sliding-window rate limiting (in-memory)
- Optional STARTTLS support
- Raw mail stored on disk for audit; import jobs created automatically

#### Web UI
- AdminLTE 4 / Bootstrap 5 server-side rendered interface (Jinja2)
- Dashboard: pass/fail bar chart, top source IPs, info boxes
- Domain management with per-domain and per-org inbound addresses
- DMARC report list + detail with paginated record view
- Source IP list with manual classification
- Alert rules, events (acknowledge / resolve), notification channels
- Import job list + detail with error breakdown
- SMTP status, message log, rejection log (superadmin)
- API token management (raw token shown only once via session flash)
- Organization and user management

#### REST API (`/api/v1/`)
- Bearer token authentication (SHA-256 stored, never stored in plaintext)
- Endpoints: `/health`, `/version`, `/me`, `/domains`, `/reports`, `/source-ips`,
  `/alerts/events`, `/inbound-addresses`, `/smtp/status`

#### Alerting
- Rule-based alert engine (no AI/ML): high fail rate, policy active with failures,
  unknown sources, DKIM missing, stale reports, ready for `quarantine`/`reject`
- Cooldown support (`next_allowed_at`) per rule to prevent notification storms
- Notification channels: webhook, ntfy, Slack-compatible webhook
- Alert event lifecycle: `open` → `acknowledged` → `resolved`

#### Recommendations
- Rule-based per-domain recommendations: 10 actionable rules covering
  no inbound address, stale reports, `pct < 100`, policy progression, high fail rate, etc.

#### Infrastructure
- Multi-stage Docker build (non-root `appuser`, minimal runtime image)
- `docker-compose.yml` with PostgreSQL, web, and smtp services
- Alembic migration setup with `Base.metadata.create_all()` fallback for first run
- `Makefile` with `install`, `test`, `cov`, `lint`, `run`, `smtp`, `migrate`, `upgrade`, `image`
- GitHub Actions: test matrix (Python 3.11/3.12), lint, Docker build + GHCR push
- `.env.example` with all required variables documented

#### Security
- Passwords hashed with bcrypt (passlib)
- API tokens: `(raw, sha256)` — raw returned once, hash stored
- Session-based web auth with `itsdangerous` + `SessionMiddleware`
- Audit log table for sensitive actions
- `TRUSTED_PROXIES` config for `X-Forwarded-For` trust

#### Tests
- `conftest.py`: in-memory SQLite fixtures, sample DMARC XML constants
- `test_dmarc_evaluator.py`: 30+ cases covering alignment, policy, stats
- `test_dmarc_parser.py`: valid/broken/XXE XML, record parsing, max-records truncation
- `test_mime_parser.py`: ZIP, gzip, MIME attachment extraction, bomb protection
- `test_smtp_inbound.py`: RCPT validation, rate limiting
- `test_import_service.py`: full import pipeline, deduplication, source IP tracking
- `test_tenant_isolation.py`: cross-tenant isolation for reports, records, domains, IPs

[Unreleased]: https://github.com/yourorg/dmarc-analyzer/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yourorg/dmarc-analyzer/releases/tag/v0.1.0
