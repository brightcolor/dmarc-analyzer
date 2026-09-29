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
- **Absender mit Namen**: Jede IP-Adresse wird einem Dienst zugeordnet, etwa Google, Microsoft 365,
  Amazon SES, Mailchimp oder IONOS. Ein Klick gibt einen Dienst mit allen seinen Adressen frei, auch mit
  künftigen.
- **Alarme** für 13 Auffälligkeiten, von neuen unbekannten Quellen über steigende Fehlerquoten bis zu
  ausbleibenden Berichten. Benachrichtigung per E-Mail, Webhook, ntfy oder Slack und Mattermost.
- **Wochenbericht** per Mail mit Bestehensquote, Quellen mit Fehlern, neuen Quellen, offenen Alarmen
  und Empfehlungen.
- **Aufräumen nach Frist**: alte Berichte, Importe, Rohmails und abgelehnte Zustellversuche verschwinden
  nach den eingestellten Tagen.
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

## Absender mit Namen

Unter **Quellen → Absender** stehen die Dienste, die für deine Domains Mails verschicken, mit Zahl der
IP-Adressen, Nachrichten und Bestehensquote. **Freigeben** stuft alle Adressen des Dienstes als
vertrauenswürdig ein, auch Adressen, die er später nutzt; **Verdächtig** macht das Gegenteil,
**Aufheben** nimmt die Entscheidung zurück. Eine Adresse, die jemand einzeln eingestuft hat, behält
ihre Einstufung. Neue Adressen eines freigegebenen Dienstes lösen keinen Alarm „Neue unbekannte
Versandquelle“ aus.

Der Zeitplaner ordnet neue Adressen im Takt von `SENDER_LOOKUP_INTERVAL_SECONDS` zu und prüft
bekannte nach `SENDER_LOOKUP_REFRESH_DAYS` erneut. Als Nachweis zählen, in dieser Reihenfolge:

1. der Hostname der Adresse, wenn er per DNS wieder auf dieselbe Adresse zeigt,
2. eine bestandene DKIM-Signatur von einer Domain des Dienstes,
3. bestandenes SPF für die Bounce-Domain des Dienstes.

Den Netzbetreiber (AS-Nummer, Name, Land) holt die Anwendung über den DNS-Dienst von Team Cymru.
Ohne DNS-Abfragen (`SENDER_LOOKUP_ENABLED=false`) erkennt sie Dienste nur über DKIM und SPF.

Die Dienste stehen im Katalog `app/data/sender_catalog.json`. Eigene Einträge kommen in eine
JSON-Datei gleichen Aufbaus, deren Pfad `SENDER_CATALOG_PATH` nennt; gleiche Schlüssel ersetzen
eingebaute Einträge:

```json
{"senders": [
  {"key": "beispiel-crm", "name": "Beispiel-CRM", "kind": "app",
   "rdns": ["mail.crm.example.net"], "dkim": ["crm.example.net"], "spf": ["bounce.crm.example.net"]}
]}
```

`kind` ist `mailbox` (Postfachanbieter), `esp` (Versanddienst), `app` (Anwendung) oder `hosting`
(Webhoster). Fehler in der Datei zeigt die Seite „Absender“ dem Betreiber.

---

## Alarme und Wochenbericht

### Regeln

Unter **Alarme → Regeln** legst du fest, wann die Anwendung Alarm schlägt. Jede Regel hat eine Art,
optional eine Domain, eine Schwelle, einen Zeitraum und eine Pause nach dem Alarm. Die Anwendung prüft
alle Regeln direkt nach jedem Import und zusätzlich im Takt von `ALERT_EVAL_INTERVAL_SECONDS`.

| Art | Schlägt an, wenn … | Schwelle ohne eigenen Wert |
|---|---|---|
| Neue unbekannte Versandquelle | eine Quelle zum ersten Mal auftaucht und noch nicht eingestuft ist | – |
| Neue Quelle mit vielen Nachrichten | eine neue Quelle viele Nachrichten verschickt | `ALERT_DEFAULT_HIGH_VOLUME` |
| Neue Quelle mit DMARC-Fehlern | eine neue Quelle Nachrichten ohne DMARC-Erfolg verschickt | `ALERT_DEFAULT_NEW_SOURCE_FAILURES` |
| DMARC-Fehlerquote über der Schwelle | der Anteil ohne DMARC-Erfolg die Schwelle erreicht | `ALERT_DEFAULT_FAIL_RATE` |
| Viele Nachrichten ohne passendes SPF oder DKIM | der Anteil ohne passendes SPF bzw. DKIM die Schwelle erreicht | `ALERT_DEFAULT_AUTH_FAIL_RATE` |
| Versandmenge steigt oder fällt plötzlich | die Menge vom Durchschnitt der Zeiträume davor abweicht | `ALERT_DEFAULT_VOLUME_SPIKE`, `ALERT_DEFAULT_VOLUME_DROP` |
| Berichte bleiben aus | im Zeitraum kein Bericht ankam | – |
| Import fehlgeschlagen | Dateien sich nicht importieren ließen | `ALERT_DEFAULT_IMPORT_FAILURES` |
| Domain bereit für eine strengere Policy | die Zahlen `p=quarantine` oder `p=reject` tragen | – |
| Viele Mails an unbekannte Adressen | der Mailempfang viele Mails an unbekannte Adressen ablehnt (nur Betreiber) | `ALERT_DEFAULT_INVALID_RECIPIENTS` |
| Grenze für eingehende Mails erreicht | Absender die Mailgrenze treffen (nur Betreiber) | `ALERT_DEFAULT_RATE_LIMIT_HITS` |

Eine Regel meldet denselben Befund erst wieder, wenn der vorige Alarm erledigt ist, und wartet nach
jedem Alarm ihre Pause ab. So kommt eine neue Quelle genau einmal.

### Kanäle

Unter **Alarme → Kanäle** legen Administratoren fest, wohin Alarme gehen. Der Knopf **Testen** schickt
sofort eine Probenachricht. Klappt die Zustellung nicht, versucht die Anwendung es bis zu
`NOTIFICATION_RETRY_MAX` Mal erneut; die Wartezeit beginnt bei `NOTIFICATION_RETRY_DELAY_SECONDS` und
verdoppelt sich mit jedem Versuch. Den Grund eines Fehlschlags zeigen Kanalliste und Alarm.

| Kanal | Einstellungen | Was ankommt |
|---|---|---|
| E-Mail | Empfänger, eine Adresse je Zeile | Mail im Stil von bright color, mit Nur-Text-Fassung |
| Webhook | Adresse | JSON, siehe unten |
| ntfy | Thema, optional eigener Server und Zugangstoken | Nachricht mit Titel, Priorität nach Schwere und Link |
| Slack oder Mattermost | Adresse des eingehenden Webhooks | Nachricht mit Farbe nach Schwere |

Der Webhook bekommt:

```json
{
  "id": "…", "type": "dmarc_fail_rate", "severity": "warning",
  "title": "12,5 % scheitern an DMARC für example.org", "description": "…",
  "status": "open", "domain": "example.org", "source_ip": null,
  "metrics": {"rate": 12.5, "failed": 25, "total": 200, "threshold": 10.0},
  "created_at": "2026-09-28T10:00:00+00:00", "url": "https://dmarc.example.com/alerts/events?status=open"
}
```

### Wochenbericht

Einmal pro Woche bekommt jede Organisation eine Mail mit den Zahlen der letzten
`DIGEST_PERIOD_DAYS` Tage: Bestehensquote mit Vergleich zum Zeitraum davor, Domains, Quellen mit
Fehlern, neue Quellen, offene Alarme, Empfehlungen und die Berichtsformate. Vorgabe ist montags ab
8 Uhr (`DIGEST_WEEKDAY`, `DIGEST_HOUR` in `DISPLAY_TIMEZONE`).

Unter **Alarme → Wochenbericht** siehst du den nächsten Termin, kannst die Mail als Vorschau öffnen,
sie sofort verschicken und Empfänger eintragen. Ohne Eintrag geht sie an alle Administratoren der
Organisation; jede Person bekommt eine eigene Mail.

### Mailversand einrichten

E-Mail-Kanäle und der Wochenbericht brauchen einen SMTP-Server. Trage ihn in die `.env` ein und
starte den Web-Container neu:

```bash
MAIL_SMTP_HOST=smtp.example.com
MAIL_SMTP_PORT=587
MAIL_SMTP_SECURITY=starttls
MAIL_SMTP_USER=dmarc@example.com
MAIL_SMTP_PASSWORD=…
MAIL_FROM=DMARC Analyzer <dmarc@example.com>
```

Links, Logo und Schriften in den Mails zeigen auf `APP_URL`. Ob der Mailversand eingerichtet ist,
sieht der Betreiber unter **Empfang → Status**.

### Zeitplaner und Aufräumen

Der Zeitplaner läuft im Web-Container. Er prüft Regeln, verschickt Benachrichtigungen, sucht fällige
Wochenberichte und räumt auf. Jede Aufgabe läuft pro Takt genau einmal, auch mit mehreren
Web-Containern. Letzten Lauf und Ergebnis jeder Aufgabe zeigt **Empfang → Status** dem Betreiber.

Beim Aufräumen löscht die Anwendung Berichte, Importe samt Dateien und empfangene Mails, die älter
sind als die Aufbewahrung der Organisation (`report_retention_days`, Vorgabe 365 Tage). Rohmails gehen
nach `SMTP_INBOUND_RAW_RETENTION_DAYS`, abgelehnte Zustellversuche nach
`SMTP_REJECTION_RETENTION_DAYS`. Ein Lauf löscht höchstens `RETENTION_BATCH_SIZE` Einträge je Art.

---

## Einstellungen

Alle Einstellungen kommen aus Umgebungsvariablen oder der `.env`. Die Datei
[`.env.example`](.env.example) nennt die wichtigen mit Erklärung. Ungültige Werte stoppen den
Start mit einer Meldung, welche Einstellung welche Grenze verletzt.

| Variable | Vorgabe | Wofür |
|---|---|---|
| `SECRET_KEY` | zufällig je Start | signiert die Sitzungen; eigener Wert, damit Anmeldungen einen Neustart überstehen |
| `DATABASE_URL` | SQLite im Arbeitsordner | Datenbank; Compose setzt PostgreSQL |
| `APP_URL` | `http://localhost:8000` | öffentliche Adresse für Einrichtungshinweis und Links in Mails |
| `SESSION_HTTPS_ONLY` | `false` | Sitzungscookie nur über HTTPS |
| `SMTP_INBOUND_DOMAIN` | `reports.example.org` | Domain der Empfangsadressen |
| `DISPLAY_TIMEZONE` | `Europe/Berlin` | Zeitzone der Oberfläche |
| `UI_CHART_DAYS` | `30` | Tage im Verlaufsdiagramm |
| `RECOMMENDATION_*` | siehe `.env.example` | Schwellen der Empfehlungen |
| `ARCHIVE_MAX_*` | 20 MB, 50 MB, 50 Dateien | Grenzen für Anhänge und Archive |
| `SETUP_OPEN_PATHS` | `/static,/api,/health,…` | Pfade, die während der Ersteinrichtung offen bleiben |
| `MAIL_SMTP_*`, `MAIL_FROM` | Versand aus | SMTP-Server für Alarme und Wochenbericht |
| `DIGEST_*` | montags, 8 Uhr, 7 Tage | Termin und Inhalt des Wochenberichts |
| `ALERT_DEFAULT_*` | siehe `.env.example` | Schwellen für Regeln ohne eigenen Wert |
| `NOTIFICATION_*`, `NTFY_DEFAULT_URL` | 3 Versuche, `https://ntfy.sh` | Wiederholungen und Zeitlimits der Benachrichtigungen |
| `SCHEDULER_ENABLED`, Takte `*_INTERVAL_SECONDS` | an | Zeitplaner im Web-Container |
| `RETENTION_*`, `SMTP_REJECTION_RETENTION_DAYS` | täglich, 30 Tage | Aufräumen |
| `SENDER_LOOKUP_*`, `SENDER_ASN_*` | an, jede Minute, 30 Tage | Zuordnung der Absender per DNS |
| `SENDER_CATALOG_PATH` | leer | eigener Absenderkatalog |
| `DNS_NAMESERVERS` | die des Systems | DNS-Server für das Nachschlagen |

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
