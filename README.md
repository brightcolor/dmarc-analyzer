# DMARC Analyzer

Selbst gehostete Auswertung von DMARC-Sammelberichten für mehrere Organisationen. Die Anwendung
nimmt Berichte über einen eigenen Mailempfang an, wertet sie aus und zeigt in einer
Weboberfläche, wer im Namen deiner Domains Mails verschickt, was DMARC besteht und was nicht.

Sie liest beide Fassungen von DMARC: RFC 7489 von 2015 und DMARCbis von 2026 (RFC 9989 und
RFC 9990). Jeder Bericht zeigt, in welchem Format er ankam und woran das erkannt wurde.

---

## Funktionen

- **Eigener Mailempfang** mit aiosmtpd: nimmt nur Mails an die Empfangsadressen der Organisationen
  an, lehnt Unbekannte schon bei `RCPT TO` ab und leitet nichts weiter.
- **Beide Berichtsformate**: RFC 7489 und RFC 9990, mit und ohne Namespace. Die Auswertung kennt
  den Testmodus `t`, die Policy `np` für nicht existierende Subdomains, `pct` und die Behandlung
  `pass`.
- **Empfehlungen je Domain**, etwa bereit für `p=quarantine` oder `p=reject`, `pct=0` ohne `t=y`,
  unbekannte Quellen und fehlende Berichte. Alle Schwellen sind einstellbar.
- **DNS-Vorschlag** für den DMARC-Eintrag, der für Empfänger beider Standards passt, und für den
  Zustimmungseintrag unter `_report._dmarc`.
- **Mehrere Organisationen** mit getrennten Daten, Rollen und API-Tokens.
- **Sicher beim Einlesen**: XML mit `defusedxml`, Grenzen für ZIP und GZ gegen Archivbomben.
- **Weboberfläche** in der Werkbank von bright color, hell und dunkel, auf Deutsch.
- **REST-API** mit Bearer-Token.

---

## Schnellstart mit Docker Compose

```bash
git clone https://github.com/brightcolor/dmarc-analyzer.git && cd dmarc-analyzer && cp .env.example .env && docker compose up -d
```

Setze vorher in der `.env` mindestens `POSTGRES_PASSWORD`, `SECRET_KEY`, `APP_URL` und
`SMTP_INBOUND_DOMAIN`. Die Weboberfläche läuft auf Port `8765`, der Mailempfang auf Port `2525`.

### Ersteinrichtung

Solange es kein Administratorkonto gibt, führt jede Seite zur Ersteinrichtung unter `/auth/setup`.
Dort legst du das erste Konto und die erste Organisation an. Die Seite verlangt einen
Einrichtungscode, den nur sieht, wer den Server betreibt:

```bash
docker compose exec web python -m app.setup_code
```

Der Code steht auch im Log beim Start (`docker compose logs web`). Er gilt einmal. Sobald ein
Administrator existiert, antwortet `/auth/setup` mit 404. Healthcheck, API und statische Dateien
bleiben während der Einrichtung erreichbar.

---

## DNS einrichten

1. **MX-Eintrag für die Empfangsdomain**, damit Empfänger ihre Berichte zustellen können:

   ```
   reports.example.com.  MX 10  server.example.com.
   ```

   Zeigt Port 25 nicht direkt auf den Container, leitet eine Portweiterleitung oder ein Mailserver
   auf Port `2525` weiter.

2. **DMARC-Eintrag je Domain.** Die Domainseite zeigt den passenden Wert zum Kopieren, etwa:

   ```
   _dmarc.example.com.  TXT  "v=DMARC1; p=none; rua=mailto:dom-example-com-abc123@reports.example.com"
   ```

3. **Zustimmung der Empfangsdomain.** Liegt die Empfangsadresse auf einer anderen Domain als die
   ausgewertete, stellen Empfänger Berichte erst zu, wenn die Empfangsdomain zustimmt. Diesen
   Eintrag setzt, wer die Zone der Empfangsdomain verwaltet:

   ```
   example.com._report._dmarc.reports.example.com.  TXT  "v=DMARC1"
   ```

   Ein Platzhaltereintrag `*._report._dmarc.reports.example.com` stimmt für alle Domains zu.

---

## DMARC 2015 und DMARCbis

Seit Mai 2026 ersetzen RFC 9989 (DMARC), RFC 9990 (Sammelberichte) und RFC 9991 (Fehlerberichte)
den RFC 7489. Der DNS-Eintrag bleibt `v=DMARC1`. Die wichtigsten Unterschiede:

| Thema | RFC 7489 | RFC 9989 und 9990 |
|---|---|---|
| Policy für einen Teil der Mails | `pct` | entfällt |
| Testbetrieb | meist `pct=0` | `t=y` |
| Nicht existierende Subdomains | `sp`, sonst `p` | `np`, sonst `sp`, sonst `p` |
| Organisationsdomain | Public Suffix List | DNS-Tree-Walk |
| Aufbau der Berichte | XML ohne Namespace | Namespace `urn:ietf:params:xml:ns:dmarc-2.0`, neue Felder |

Die Anwendung erkennt RFC-9990-Berichte am Namespace oder, wenn er fehlt, an Feldern, die es nur
dort gibt (`np`, `testing`, `discovery_method`, `generator`, Behandlung `pass`, Grund
`policy_test_mode`). Alle übrigen liest sie nach RFC 7489. Die Seite **Hilfe → DMARC-Formate**
erklärt das ausführlich und zeigt, welcher Empfänger in welchem Format berichtet.

---

## Einstellungen

Alle Einstellungen kommen aus Umgebungsvariablen oder der `.env`. Die Datei
[`.env.example`](.env.example) nennt die wichtigen mit Erklärung. Ungültige Werte stoppen den
Start mit einer Meldung, welche Einstellung welche Grenze verletzt.

| Variable | Vorgabe | Wofür |
|---|---|---|
| `SECRET_KEY` | zufällig je Start | signiert die Sitzungen; eigener Wert, damit Anmeldungen einen Neustart überstehen |
| `DATABASE_URL` | SQLite im Arbeitsordner | Datenbank; Compose setzt PostgreSQL |
| `APP_URL` | `http://localhost:8000` | öffentliche Adresse, erscheint im Einrichtungshinweis |
| `SESSION_HTTPS_ONLY` | `false` | Sitzungscookie nur über HTTPS |
| `SMTP_INBOUND_DOMAIN` | `reports.example.org` | Domain der Empfangsadressen |
| `DISPLAY_TIMEZONE` | `Europe/Berlin` | Zeitzone der Oberfläche |
| `UI_CHART_DAYS` | `30` | Tage im Verlaufsdiagramm |
| `RECOMMENDATION_*` | siehe `.env.example` | Schwellen der Empfehlungen |
| `ARCHIVE_MAX_*` | 20 MB, 50 MB, 50 Dateien | Grenzen für Anhänge und Archive |
| `SETUP_OPEN_PATHS` | `/static,/api,/health,…` | Pfade, die während der Ersteinrichtung offen bleiben |

---

## Datenbank und Updates

Beim Start bringt die Anwendung das Schema mit Alembic auf den neuesten Stand
(`python -m app.migrate`). Datenbanken aus Version 0.1.0, die noch ohne Migrationsverlauf
angelegt wurden, übernimmt sie dabei automatisch.

Sicherung und Wiederherstellung:

```bash
docker compose exec db pg_dump -U dmarc dmarc > sicherung.sql
docker compose exec -T db psql -U dmarc dmarc < sicherung.sql
```

Hochgeladene Dateien und Rohmails liegen in den Bind Mounts `./data/uploads` und `./data/raw_mail`.

---

## Lokale Entwicklung

```bash
python -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
DATABASE_URL=sqlite:///./demo.db python scripts/demo_data.py   # erfundene Beispieldaten
DATABASE_URL=sqlite:///./demo.db python scripts/dev_server.py  # http://127.0.0.1:8766
```

Das Demo-Skript legt eine Organisation mit drei Domains und vier Wochen Berichten in beiden
Formaten an und schreibt die Anmeldung in `demo-login.txt`. Es läuft nur gegen SQLite.

Tests und Prüfung:

```bash
pytest
ruff check app smtp_inbound
```

---

## API

Alle Routen liegen unter `/api/v1/` und brauchen einen Token aus **Verwaltung → API-Tokens**:

```bash
curl -H "Authorization: Bearer <token>" https://dmarc.example.com/api/v1/reports
```

| Methode | Pfad | Inhalt |
|---|---|---|
| GET | `/api/v1/health` | Healthcheck, ohne Anmeldung |
| GET | `/api/v1/version` | Version |
| GET | `/api/v1/me` | Token und Organisation |
| GET | `/api/v1/domains` | Domains |
| GET | `/api/v1/domains/{id}/stats` | Kennzahlen einer Domain |
| GET | `/api/v1/reports` | Berichte mit Format (`report_format`, `format_evidence`) und Policy |
| GET | `/api/v1/source-ips` | Versandquellen |
| GET | `/api/v1/alerts/events` | Alarme |
| POST | `/api/v1/alerts/events/{id}/acknowledge` | Alarm bestätigen |
| GET | `/api/v1/inbound-addresses` | Empfangsadressen |
| GET | `/api/v1/smtp/status` | Zustand des Mailempfangs |

Die vollständige Beschreibung steht unter `/api/docs`.

---

## Sicherheit

Hinweise zum Melden von Schwachstellen stehen in [SECURITY.md](SECURITY.md).

## Lizenz

[MIT](LICENSE)
