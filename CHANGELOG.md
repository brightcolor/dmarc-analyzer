# Changelog

Alle wichtigen Änderungen an DMARC Analyzer. Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/),
Versionen nach [SemVer](https://semver.org/lang/de/).

---

## [Unreleased]

## [0.5.1] – 2026-09-29

### Behoben

- Die Organisationsdomain für das Alignment kommt aus der Public Suffix List. `mail.example.co.uk`
  gehört damit zu `example.co.uk`, und Kunden gemeinsamer Domains wie `github.io` bleiben getrennt.
  Eine neuere Fassung der Liste kann der Betreiber über `PUBLIC_SUFFIX_LIST_PATH` einbinden.
- Eine geleerte Notiz an einer IP-Adresse wird gespeichert.

### Geändert

- Abhängigkeiten aktualisiert: FastAPI 0.136, Starlette 1.2, pydantic 2.13, Jinja2 3.1.6,
  python-multipart 0.0.29 und psycopg2 2.9.12; dazu pytest 9 und die GitHub Actions für Build und
  Tests.
- Nicht genutzte Pakete entfernt: python-jose, aiofiles, APScheduler, slowapi, limits und
  email-validator.
- Formulare mit leerem Pflichtfeld zeigen die Meldung der jeweiligen Seite.

## [0.5.0] – 2026-09-29

### Neu

- Rollen wirken: Lesezugriff sieht alles; Analysten laden Berichte hoch, stufen IP-Adressen und
  Absender ein und bearbeiten Alarme; Manager verwalten Domains und Alarmregeln; Administratoren
  Kanäle, Wochenbericht, Mitglieder und API-Tokens. Die Oberfläche zeigt jeder Rolle nur die Formulare,
  die sie nutzen darf, und nennt sonst die nötige Rolle.
- Formulare zählen nur, wenn sie von der Anwendung selbst kommen (`Origin` bzw. `Referer`); weitere
  Adressen der Oberfläche trägt der Betreiber in `CSRF_TRUSTED_ORIGINS` ein.
- Sperre gegen Raten: Nach zu vielen Fehlversuchen je Konto oder je Adresse sperrt die Anmeldung für
  eine einstellbare Zeit; die Meldung nennt das Ende der Sperre. Der Einrichtungscode ist genauso
  geschützt.
- Webhook, ntfy und Slack gehen nur an öffentliche Adressen. Die Anwendung prüft das beim Anlegen eines
  Kanals und vor jedem Versand; interne Dienste gibt der Betreiber über
  `NOTIFICATION_ALLOWED_INTERNAL_HOSTS` frei.
- Die Grenzen des Standardtarifs für neue Organisationen sind Einstellungen (`DEFAULT_PLAN_*`).

### Geändert

- `X-Forwarded-For` zählt nur noch, wenn die Verbindung von einem Proxy aus `TRUSTED_PROXIES` kommt;
  die Einstellung nimmt jetzt auch Netze wie `172.16.0.0/12`.
- Das Aufräumen löscht alte Anmeldeversuche nach `LOGIN_ATTEMPT_RETENTION_DAYS`.

## [0.4.0] – 2026-09-29

### Neu

- Absender mit Namen: Jede IP-Adresse wird einem Dienst zugeordnet, etwa Google, Microsoft 365,
  Amazon SES, Mailchimp, SendGrid, Postmark, IONOS, Strato oder ALL-INKL.COM. Als Nachweis zählen ein
  Hostname, der per DNS wieder auf die Adresse zeigt, eine bestandene DKIM-Signatur des Dienstes und
  bestandenes SPF für seine Bounce-Domain.
- Neue Seite „Quellen → Absender“: Dienste mit IP-Adressen, Nachrichten und Bestehensquote. Ein Klick
  gibt einen Dienst frei oder stuft ihn als verdächtig ein; das gilt für alle seine Adressen, auch für
  künftige. Einzeln eingestufte Adressen behalten ihre Einstufung.
- Neue Adressen eines freigegebenen Dienstes lösen keinen Alarm „Neue unbekannte Versandquelle“ mehr
  aus. Alarme, Wochenbericht, Übersicht und API nennen den Dienst zur Adresse.
- Hostname, AS-Nummer, Netzbetreiber und Land jeder Quelle kommen per DNS (Team Cymru); der
  Zeitplaner schlägt neue Quellen nach und prüft bekannte regelmäßig erneut. „Jetzt erkennen“ startet
  das sofort.
- Der Absenderkatalog lässt sich über eine eigene JSON-Datei (`SENDER_CATALOG_PATH`) ergänzen.
- Die Liste der IP-Adressen lässt sich nach Absender filtern und nach Hostname durchsuchen.

### Geändert

- Die Spalte für die berichtende Stelle heißt jetzt „Berichtet von“; „Absender“ meint die Dienste, die
  Mails verschicken.
- Die ungenutzten Einstellungen `DNS_ENRICHMENT_*` und `FEATURE_SOURCE_ENRICHMENT` sind entfallen; an
  ihre Stelle treten `SENDER_LOOKUP_*`.

## [0.3.0] – 2026-09-29

### Neu

- Alarme arbeiten: Die Anwendung prüft alle Regeln direkt nach jedem Import und zusätzlich im Takt von
  `ALERT_EVAL_INTERVAL_SECONDS`. Alle 13 Arten werten aus, darunter SPF- und DKIM-Quoten, plötzlich
  steigende oder fallende Versandmengen, neue Quellen mit vielen Nachrichten oder DMARC-Fehlern,
  fehlgeschlagene Importe und Domains, die für eine strengere Policy bereit sind.
- Jeder Befund kommt genau einmal: Eine Regel meldet ihn wieder, sobald der vorige Alarm erledigt ist
  und ihre Pause abgelaufen ist.
- Benachrichtigungen gehen raus, per E-Mail, Webhook, ntfy und Slack oder Mattermost. Scheitert eine
  Zustellung, versucht die Anwendung es mit wachsendem Abstand erneut; Kanalliste und Alarm nennen den
  Grund. Jeder Kanal hat einen Knopf „Testen“.
- Kanäle entstehen über eigene Felder für Empfänger, Adresse, Thema und Zugangstoken. Die Liste zeigt
  Ziel und letzte Zustellung; Token und der geheime Teil von Webhook-Adressen bleiben verborgen.
- Wochenbericht per Mail mit Bestehensquote und Vergleich zur Vorwoche, Domains, Quellen mit Fehlern,
  neuen Quellen, offenen Alarmen, Empfehlungen und Berichtsformaten. Er geht montags ab 8 Uhr an die
  Administratoren der Organisation oder an eingetragene Empfänger. Die neue Seite
  „Alarme → Wochenbericht“ bietet Vorschau, „Jetzt senden“ und die Einstellungen.
- Mailversand über einen SMTP-Server aus der `.env` (`MAIL_SMTP_*`, `MAIL_FROM`). Alarm- und
  Berichtsmails kommen im Stil von bright color und mit Nur-Text-Fassung.
- Zeitplaner im Web-Container für Alarme, Benachrichtigungen, Wochenbericht und Aufräumen. Jede Aufgabe
  läuft je Takt einmal, auch mit mehreren Containern. „Empfang → Status“ zeigt dem Betreiber den
  Mailversand und die letzten Läufe.
- Aufräumen nach Frist: Berichte, Importe samt Dateien und empfangene Mails nach der Aufbewahrung der
  Organisation, Rohmails nach `SMTP_INBOUND_RAW_RETENTION_DAYS`, abgelehnte Zustellversuche nach
  `SMTP_REJECTION_RETENTION_DAYS`.
- Die Regelseite erklärt, was jede Art prüft und welche Schwelle ohne eigenen Wert gilt.
- Nach dem Speichern, Testen oder Senden zeigt die Seite oben, was passiert ist.
- Alle neuen Schwellen, Takte und Grenzen sind Einstellungen mit geprüften Grenzen; `.env.example`
  nennt sie.

### Geändert

- Kanäle anlegen, testen und löschen sowie den Wochenbericht einstellen dürfen die Administratoren der
  Organisation.
- Die Alarmarten für den Mailempfang des ganzen Servers stehen nur dem Betreiber zur Wahl.
- Empfehlungen schreiben Zahlen in deutscher Schreibweise und unterscheiden Einzahl und Mehrzahl.
- Meldungen des Mailempfangs zu einzelnen Mails sind auf Deutsch.

### Behoben

- GZ-Berichte mit Zeilenumbruch oder Füllbytes hinter den Daten, wie sie etwa Mimecast verschickt,
  werden gelesen, ebenso GZ-Dateien aus mehreren Teilen.
- Dateinamen von Anhängen und Uploads kommen mit einem sicheren Zeichensatz auf die Platte.
- Neue Quellen zeigen ihre Bestehensquote ab dem ersten Bericht.

## [0.2.1] – 2026-09-29

### Behoben

- Schriften und Logos gehen mit dem passenden Medientyp (`font/woff2`, `image/svg+xml`) an den Browser.
  Im schlanken Container-Abbild kamen sie bisher als `text/plain`.

## [0.2.0] – 2026-09-29

### Neu

- Berichte nach DMARCbis (RFC 9989 und RFC 9990) werden gelesen, mit und ohne Namespace
  `urn:ietf:params:xml:ns:dmarc-2.0`. Berichte nach RFC 7489 laufen weiter wie bisher.
- Jeder Bericht zeigt sein Format (RFC 7489 oder RFC 9990) und woran es erkannt wurde; Berichtsliste,
  Domainseite und Übersicht zeigen, welcher Empfänger in welchem Format berichtet. Die Berichtsliste
  lässt sich nach Format filtern.
- Neue Seite „Hilfe → DMARC-Formate“ mit den Unterschieden beider Fassungen.
- Die Auswertung kennt den Testmodus `t`, die Policy `np`, `discovery_method`, `generator` und die
  Behandlung `pass`; Override-Gründe der Empfänger werden gespeichert und angezeigt.
- Empfehlungen zu `pct=0` ohne `t=y`, zu `pct` unter 100 und zum aktiven Testmodus.
- Der DNS-Vorschlag übernimmt `sp`, `np`, `t` und `pct`, sodass derselbe Eintrag für Empfänger beider
  Standards passt; Name und Wert lassen sich kopieren.
- Oberfläche neu in der Werkbank von bright color, auf Deutsch, hell und dunkel. Schriften, Skripte und
  Diagramme liefert die Anwendung selbst aus.
- Ersteinrichtung mit Einrichtungscode: Solange es keinen Administrator gibt, führt jede Seite zur
  Einrichtung. Den Code zeigt `python -m app.setup_code` oder das Log beim Start.
- Die REST-API liefert zu jedem Bericht Format, Nachweis und Policy-Felder.
- Schwellen, Zeiträume und Grenzen für Empfehlungen, Oberfläche und Archive sind Einstellungen mit
  geprüften Grenzen; ungültige Werte stoppen den Start mit einer verständlichen Meldung.
- Datenbankschema über Alembic-Migrationen; Datenbanken aus 0.1.0 werden beim Start übernommen.
- `scripts/demo_data.py` legt erfundene Beispieldaten für die lokale Entwicklung an.

### Geändert

- Subdomains ohne `sp` werden nach `p` bewertet. Bisher galt dort fälschlich `none`.
- Das Verlaufsdiagramm ordnet Nachrichten dem Tag zu, an dem sie verschickt wurden (Berichtszeitraum).
- Fehlermeldungen von Import, Upload, Formularen und Fehlerseiten sind deutsch und nennen den nächsten
  Schritt; interne Pfade erscheinen nicht mehr.
- Benutzer und API-Tokens verwalten nur noch Administratoren der Organisation; neue Organisationen
  legt nur der Betreiber an; abgelehnte Empfänger sieht nur der Betreiber.
- `INITIAL_ADMIN_EMAIL` und `INITIAL_ADMIN_PASSWORD` entfallen; das erste Konto entsteht in der
  Ersteinrichtung.
- `.env.example` nennt nur noch Einstellungen, die die Anwendung auch liest.

### Sicherheit

- Hochgeladene Dateinamen können den Upload-Ordner nicht mehr verlassen.
- Die Weiterleitung nach der Anmeldung führt nur noch auf Seiten der Anwendung.
- Ein leerer, zu kurzer oder aus der Vorlage übernommener `SECRET_KEY` wird durch einen zufälligen
  ersetzt und im Log gemeldet.

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

[Unreleased]: https://github.com/brightcolor/dmarc-analyzer/compare/v0.5.1...HEAD
[0.5.1]: https://github.com/brightcolor/dmarc-analyzer/releases/tag/v0.5.1
[0.5.0]: https://github.com/brightcolor/dmarc-analyzer/releases/tag/v0.5.0
[0.4.0]: https://github.com/brightcolor/dmarc-analyzer/releases/tag/v0.4.0
[0.3.0]: https://github.com/brightcolor/dmarc-analyzer/releases/tag/v0.3.0
[0.2.1]: https://github.com/brightcolor/dmarc-analyzer/releases/tag/v0.2.1
[0.2.0]: https://github.com/brightcolor/dmarc-analyzer/releases/tag/v0.2.0
[0.1.0]: https://github.com/brightcolor/dmarc-analyzer/commit/0ec5162
