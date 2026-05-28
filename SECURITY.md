# Security Policy

## Supported versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities.

Instead, email **security@yourdomain.example.com** with:
- A description of the vulnerability
- Steps to reproduce
- Potential impact
- Any proposed fix (optional)

You will receive acknowledgement within 48 hours and a resolution timeline within 7 days.

## Security design notes

- **No open relay** — the SMTP inbound server validates every recipient before accepting any data. Unknown recipients receive `550 5.1.1`; revoked/disabled addresses receive `550 5.1.1`; disabled organizations receive `550 5.7.1`. There is no silent accept-then-discard behaviour.
- **XXE protection** — all DMARC XML is parsed with `defusedxml`, which blocks DOCTYPE/external entity declarations.
- **Zip bomb protection** — ZIP and gzip attachments are extracted incrementally with a 50 MB size cap. ZIPs with more than 50 files are rejected.
- **Tenant isolation** — every database query includes an `organization_id` filter. No cross-tenant data exposure is possible through the normal code paths.
- **Token security** — API tokens are stored as SHA-256 hashes. The raw token is shown to the user exactly once (via a session flash) and is never stored or logged.
- **Password hashing** — user passwords are hashed with bcrypt (passlib, cost factor 12).
- **Session security** — web sessions use `itsdangerous` with `SECRET_KEY`. `SESSION_COOKIE_SECURE=true` should be set in production.
- **No secrets in repo** — `.env` is git-ignored; `.env.example` contains placeholder values only.
