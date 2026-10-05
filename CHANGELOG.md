# Changelog

Alle wichtigen Änderungen an DMARC Analyzer. Format nach [Keep a Changelog](https://keepachangelog.com/de/1.1.0/),
Versionen nach [SemVer](https://semver.org/lang/de/).

---

## [Unreleased]

## [0.11.6] – 2026-10-05

### Sicherheit

- python-multipart 0.0.31 und python-dotenv 1.2.2 mit den Korrekturen aus GHSA-v9pg-7xvm-68hf und
  GHSA-mf9w-mj56-hr94. Ein Test hält die Versionen mit Sicherheitskorrekturen in `requirements.txt` fest.
- Die Workflows für Tests und Lint arbeiten mit einem Token, das nur lesen darf. Jede Action in den
  Workflows ist auf einen festen Commit festgelegt, die Version steht als Kommentar daneben; Dependabot hält
  beides aktuell.
- Dependabot schlägt neue Versionen von Paketen und Actions vor, sobald sie eine Woche alt sind;
  Sicherheitsupdates kommen ohne Wartezeit.

### Neu

- Das Docker-Image prüft selbst, ob sein Dienst antwortet: die Weboberfläche über `/api/v1/health`, der
  Mailempfang über seine Begrüßung. `docker compose ps` zeigt das Ergebnis, `docker inspect` den Grund.
  Die Ziele legt `HEALTHCHECK_TARGETS` fest, das Zeitlimit je Ziel `HEALTHCHECK_TIMEOUT_SECONDS` (Vorgabe
  3 Sekunden).

## [0.11.5] – 2026-10-05

### Sicherheit

- Starlette 1.3.1 und python-multipart 0.0.30 schließen zwei Lücken, über die ein einzelnes Formular die
  Rechenleistung des Servers binden konnte (GHSA-82w8-qh3p-5jfq, GHSA-5rvq-cxj2-64vf). Die Grenzen von
  höchstens 1000 Feldern und 1 MB je Textfeld gelten damit für jedes Formular, bisher nur beim Upload. Ein
  Formular darüber lehnt die Anwendung mit einer Meldung ab, die den Grund und den nächsten Schritt nennt;
  die genaue Grenze steht im Log.
- Die Prüfung von E-Mail-Adressen bei Ersteinrichtung, Einladung, Kanälen, Wochenbericht und weiteren
  Empfängern einer Domain verkraftet auch sehr lange Eingaben. Adressen mit leerem Abschnitt in der Domain, etwa `name@example..org` oder
  `name@example.org.`, gelten jetzt als ungültig.

## [0.11.4] – 2026-10-04

### Behoben

- Für Alarme, die vor dem Versand erledigt oder ignoriert wurden, entfällt die Benachrichtigung; beim
  Alarm steht sie als „übersprungen“, den Grund nennt die Kanalliste. Eine Sammelmail führt nur die
  übrigen Alarme auf, und sind alle erledigt, entfällt die Mail. Das gilt für jeden Kanal und auch für
  neue Versuche nach einem Fehlschlag. Vorher ging die Mail nach dem Sammelzeitraum auch für schon
  behobene Probleme raus.
- Kleineres: Eine Sammelmail sortiert Alarme gleicher Schwere auch dann nach Zeit, wenn Zeitangaben mit
  und ohne Zeitzone zusammenkommen; betroffen waren nur Tests mit SQLite.

### Neu

- `NOTIFICATION_SKIP_ALERT_STATUSES` (Vorgabe `resolved,ignored`) legt fest, bei welchen Status eines
  Alarms seine wartenden Benachrichtigungen entfallen. Möglich sind `acknowledged` (gesehen), `resolved`
  und `ignored`; leer geht jede Benachrichtigung raus.

## [0.11.3] – 2026-09-30

### Behoben

- Text von außen, aus Mails, Berichten und DNS-Antworten, geht bereinigt in die Datenbank: ohne
  Null-Zeichen und andere Steuerzeichen, rohe Umlaute als UTF-8 gelesen und nach dem Kleinschreiben auf die
  Spaltenlänge gekürzt. Vorher konnte ein Null-Zeichen in einem DNS-Eintrag die Alarmprüfung bei jedem Lauf
  abbrechen, auch für andere Organisationen, und Werte wie „İ“ oder ein Null-Zeichen in TLS-Berichten
  ließen PostgreSQL die Mail ablehnen; der Absender stellte dann immer wieder zu.
- Mails mit rohen Umlauten in Betreff oder Absender führten zur endlosen Neuzustellung; jetzt stehen sie
  mit richtig lesbarem Betreff unter „Eingegangene Mails“, kodierte Wörter (`=?utf-8?…?=`) ebenso.
- Jede Alarmregel und jede Organisation läuft für sich: Bricht eine ab, prüft der Zeitplaner die übrigen.
- „Jetzt prüfen“ belegt die Domain in einem Schritt, sodass auch gleichzeitige Klicks nur eine Prüfung
  starten; während der DNS-Abfragen bleibt keine Datenbankverbindung offen.
- TLS-Berichte mit einem Zeitraum am Rand des Kalenders legten die Seiten der TLS-Berichte lahm; solche
  Berichte lehnt die Anwendung jetzt mit Grund ab, und die Anzeige verträgt auch alte Einträge.
- DKIM: Ob ein Selektor in Gebrauch ist, zählt nach dem Berichtszeitraum. Ein Upload alter Berichte macht
  alte Selektoren nicht mehr zu aktuellen.
- Kleineres: Hinweise bei unvollständiger Prüfung und bei internen Fehlern nennen den nächsten Schritt;
  „in 1 Sekunde“; `ri` bis 2^32−1; ein kleingeschriebener zweiter TLS-RPT-Eintrag zählt nicht mit; ein
  aufgebrauchtes Zeitbudget steht im Log.

### Neu

- `DNS_CHECK_MANUAL_PARALLEL` (Vorgabe 4) begrenzt gleichzeitige Prüfungen auf Knopfdruck,
  `TLS_REPORT_MAX_AGE_DAYS` (400) und `TLS_REPORT_FUTURE_TOLERANCE_HOURS` (48) den Zeitraum eines
  TLS-Berichts. `DNS_CHECK_DKIM_ACTIVE_DAYS` darf nicht über `DNS_CHECK_DKIM_DAYS` liegen.
- Tests lassen jede echte DNS-Abfrage scheitern und prüfen die Spaltenlängen gespeicherter Werte.

## [0.11.2] – 2026-09-30

### Behoben

- DNS-Prüfung: Ein ungewöhnlicher Eintrag einer einzigen Domain, etwa `pct=²` oder ein verschachtelter
  DKIM-Schlüssel, brach den ganzen Lauf des Zeitplaners ab, und die Domain blockierte danach jeden
  weiteren Lauf. Jetzt läuft jede Prüfgruppe und jede Domain für sich; was abbricht, bleibt als „keine
  Antwort“ offen, alle anderen Domains werden geprüft. „Jetzt prüfen“ und die API antworten dabei ohne
  Serverfehler.
- TLS-Berichte mit sehr langen Zahlen, Zeitpunkten außerhalb des Kalenders oder unplausibel großen
  Verbindungszahlen führten dazu, dass der Absender die Mail immer wieder zustellte. Jetzt steht die Mail
  mit Grund unter „Eingegangene Mails“, und der Absender ist fertig.
- DKIM: Fehlt der Schlüssel eines Selektors, der nur früher bestanden hat, etwa nach einem
  Schlüsselwechsel, ist das eine Warnung ohne Alarm. Ein Fehler bleibt es für Selektoren, die in den letzten
  `DNS_CHECK_DKIM_ACTIVE_DAYS` Tagen (Vorgabe 3) bestanden haben.
- `V=DMARC1` und `v = DMARC1` gelten als gültig (RFC 7489); `v=TLSRPTv1` muss genau so geschrieben sein
  (RFC 8460). Antwortet die MX-Abfrage nicht, bleibt auch die Prüfung der TLS-Berichte offen. Ein `redirect`
  neben `all` zählt nicht als SPF-Abfrage. Domains deaktivierter Organisationen prüft der Zeitplaner nicht.

### Neu

- `DNS_CHECK_DOMAIN_BUDGET_SECONDS` (Vorgabe 20) begrenzt die Zeit aller Abfragen einer Domain,
  `DNS_CHECK_JOB_BUDGET_SECONDS` (Vorgabe 120) die Zeit, in der ein Lauf neue Domains beginnt;
  `DNS_CHECK_MANUAL_COOLDOWN_SECONDS` (Vorgabe 30) sperrt „Jetzt prüfen“ kurz nach einer Prüfung, die API
  antwortet dann mit 429 und `Retry-After`.

## [0.11.1] – 2026-09-30

### Geändert

- Die DNS-Prüfung zeigt Zeichen statt Wörtern: Haken für in Ordnung, i für Hinweis, Ausrufezeichen für
  Warnung, Kreuz für Fehler, Fragezeichen für keine Antwort, jeweils in der Farbe des Zustands. Das Zeichen
  steht vor jeder Prüfung, im Kopf des Kastens und in der Spalte „DNS“ der Domainliste. Die Wörter stehen
  im Tooltip, in einer Zeile über der Liste und für Screenreader; die Spalte „Ergebnis“ fällt weg.

## [0.11.0] – 2026-09-30

### Neu

- DNS-Prüfung je Domain: DMARC-Eintrag mit Policy und Aufbau, `rua` und `ruf` mit der Empfangsadresse,
  Zustimmung der Empfangsdomain unter `_report._dmarc`, SPF mit Zählung der DNS-Abfragen samt aller
  `include` (höchstens 10, RFC 7208), die DKIM-Schlüssel der Selektoren, die in den Berichten bestanden
  haben (Länge nach RFC 8301), Mailserver und der Eintrag für TLS-Berichte. Subdomains ohne eigenen
  DMARC-Eintrag nutzen den der Organisationsdomain.
- Die Domainseite zeigt jede Prüfung mit Ampel, dem gefundenen Wert und dem richtigen Wert zum Kopieren.
  Der Vorschlag baut auf dem Eintrag im DNS auf und ergänzt nur, was fehlt; „Jetzt prüfen“ prüft sofort.
- Die Domainliste zeigt den Stand der Prüfung und filtert danach; die Übersicht nennt Domains mit Fehlern.
- Neue Alarmart „DNS-Einträge fehlerhaft“; Hinweise und Warnungen lösen keinen Alarm aus.
- Der Zeitplaner prüft jede aktive Domain nach `DNS_CHECK_MAX_AGE_SECONDS` erneut. Einstellungen
  `DNS_CHECK_*` für Takt, Menge, gleichzeitige Prüfungen, Zeitlimit und DKIM.
- API: `GET` und `POST /api/v1/domains/{id}/dns-check`; `GET /api/v1/domains` nennt den Stand der Prüfung.

## [0.10.0] – 2026-09-29

### Neu

- TLS-Berichte (TLS-RPT, RFC 8460): Mailserver wie Google und Microsoft melden einmal am Tag, wie viele
  Verbindungen zu den Mailservern einer Domain verschlüsselt zustande kamen und woran die übrigen
  scheiterten. Die Anwendung erkennt die Berichte im Mailempfang und zeigt sie unter
  **Berichte → TLS-Berichte**, mit Filter nach Domain, Absender und Ergebnis. Die Einzelansicht nennt je
  Richtlinie (MTA-STS, DANE, ohne Richtlinie) die Gründe mit einem Hinweis, was zu tun ist.
- Die Domainseite zeigt den TXT-Eintrag `_smtp._tls` mit `v=TLSRPTv1; rua=mailto:<Empfangsadresse>`
  zum Kopieren und fasst die TLS-Berichte der letzten Tage mit dem häufigsten Grund zusammen.
- Neue Alarmart „TLS-Verbindungen scheitern“ mit der Vorgabe `ALERT_DEFAULT_TLS_FAIL_RATE` (5 %); eine
  Regel für alle Domains prüft jede Domain einzeln.
- `GET /api/v1/tls-reports` liefert die Berichte mit Richtlinien und Fehlerangaben.
- Einstellungen `TLS_REPORTS_ENABLED`, `TLS_REPORT_MAX_POLICIES` und `TLS_REPORT_MAX_FAILURE_DETAILS`;
  `SMTP_INBOUND_TLS_MIN_VERSION` legt die älteste TLS-Version des Mailempfangs fest.
- Eingegangene Mails verlinken ihren TLS-Bericht. Das Aufräumen löscht TLS-Berichte mit der Aufbewahrung
  der Organisation.

### Behoben

- STARTTLS im Mailempfang: Mit `SMTP_INBOUND_TLS_ENABLED=true` verlangte der Empfang bisher TLS ab dem
  ersten Byte, wie auf Port 465. Mailserver sprechen auf Port 25 erst unverschlüsselt und wechseln mit
  STARTTLS; sie erreichten den Empfang damit nicht. Jetzt bietet er STARTTLS nach dem `EHLO` an, und
  Absender ohne TLS liefern weiter. Ein Zertifikat, das sich nicht laden lässt, schaltet nur STARTTLS
  ab; das Log nennt Pfad und Grund.

## [0.9.2] – 2026-09-29

### Geändert

- Alle Listen sind auf dem Handy zweizeilig: oben fett der Titel (Domain, Host, IP-Adresse, Name),
  darunter klein die übrigen Angaben. Knöpfe, die eine Liste braucht (Alarm bestätigen, Absender
  freigeben, Kanal testen, Token widerrufen), stehen dort als eigene Zeile darunter. Das betrifft
  Berichte, Fehlerberichte, Domains, Quellen, Absender, Alarme, Regeln, Kanäle, Empfang, Benutzer,
  API-Tokens, Organisationen und die Tabellen auf den Detailseiten.
- Die Klassen dafür kommen aus dem Werkbank-Stylesheet von bright color (`bc-row-title`,
  `bc-row-sub`, `bc-hide-narrow`, `bc-only-narrow`); `bc-workbench.css` ist auf dem Stand des Skills
  1.6.0.
- Zahlen stehen mit dem passenden Wort in Einzahl oder Mehrzahl („1 Adresse“, „2 Adressen“).

## [0.9.1] – 2026-09-29

### Geändert

- Auf dem Handy werden die Tabellen der Übersicht und die Importliste zweizeilig: oben fett der
  Absender-Host oder die Domain, darunter klein die übrigen Angaben. Die Anteilsbalken fallen dort weg.
- Berichtsdateien nach dem Namensschema `Empfänger!Domain!Beginn!Ende` erscheinen als Empfänger mit
  Domain und Berichtstag; der volle Dateiname steht im Tooltip und auf der Seite des Imports.

## [0.9.0] – 2026-09-29

### Neu

- Alarme per E-Mail kommen gebündelt: Die Anwendung sammelt sie `NOTIFICATION_EMAIL_BUNDLE_SECONDS`
  Sekunden (Vorgabe 900) und schickt dann eine Mail je Kanal oder Adresse, die wichtigsten zuerst. Ein
  einzelner Alarm behält seine eigene Mail. `NOTIFICATION_BUNDLE_MAX_ITEMS` begrenzt die Liste in
  einer Mail (Vorgabe 50), `0` schaltet das Sammeln ab. Webhook, ntfy und Slack bleiben sofort.

## [0.8.1] – 2026-09-29

### Geändert

- Eine Regel für alle Domains prüft jede aktive Domain einzeln. Jeder Alarm nennt seine Domain und
  erreicht die weiteren Empfänger dieser Domain. Vorher wertete sie alle Domains zusammen aus; eine
  einzelne Domain mit vielen Fehlern ging so unter.
- Die Pause nach einem Alarm gilt je Domain und Quelle. Ein Alarm für eine Domain hält den Alarm einer
  anderen nicht mehr auf.
- „Berichte bleiben aus“ meldet bei einer Regel für alle Domains nur Domains, die schon Berichte hatten.

### Behoben

- Alarme tragen die Zeit der Prüfung, die Pause rechnet damit.

## [0.8.0] – 2026-09-29

### Neu

- Weitere Empfänger je Domain: Auf der Domainseite trägt ein Manager Adressen ein, die die Alarme der
  Domain bekommen, einen eigenen Wochenbericht nur für ihre Domains oder beides. Eine Adresse bei
  mehreren Domains bekommt einen gemeinsamen Bericht. Grenze `DOMAIN_RECIPIENTS_MAX` (Vorgabe 20),
  Änderungen im Audit-Log.
- Der Wochenbericht lässt sich auf einzelne Domains beschränken; Betreff und Anrede nennen dann die
  Domains.
- Der vorgeschlagene DNS-Eintrag enthält `ruf` mit derselben Adresse und `fo=1`, abschaltbar mit
  `DMARC_SUGGEST_FAILURE_REPORTS=false`.

### Geändert

- Benachrichtigungen gehen an einen Kanal oder an eine einzelne Adresse. Datenbank-Migration 0007 legt
  `domain_recipients` an und ergänzt `notification_deliveries` um `recipient`.
- Die Liste der Alarme nennt bei solchen Benachrichtigungen die Adresse.

## [0.7.0] – 2026-09-29

### Neu

- Fehlerberichte (`ruf`): Der Mailempfang erkennt Berichte im Abuse Reporting Format (RFC 5965,
  RFC 6591, RFC 9991) an derselben Empfangsadresse wie die Sammelberichte. Neue Seite
  **Berichte → Fehlerberichte** mit Filter nach Domain, Quelle und gescheiterter Prüfung, Einzelansicht
  mit Prüfergebnis und Kopfzeilen der gemeldeten Mail, Löschen ab der Rolle Manager.
  `GET /api/v1/failure-reports` liefert die Berichte ohne Kopfzeilen.
- Den Inhalt der gemeldeten Mail speichert die Anwendung nie. Anhänge darin gelten nicht als
  Sammelbericht. Neue Einstellungen `FAILURE_REPORTS_ENABLED`, `FAILURE_REPORT_RETENTION_DAYS`
  (Vorgabe 30 Tage), `FAILURE_REPORT_STORE_HEADERS` und `FAILURE_REPORT_MAX_HEADER_BYTES`.
- Mailversand über die HTTP-API von Postal: `MAIL_BACKEND=postal` mit `POSTAL_API_URL`,
  `POSTAL_API_KEY` und `POSTAL_MESSAGE_TAG`. Hilft auf Hosts, deren Anbieter ausgehenden Port 25
  sperrt.
- `python -m app.mail_check` prüft den Mailversand, ohne eine Mail zu verschicken.
- Eingegangene Mails mit Fehlerbericht verlinken auf den Bericht.

### Geändert

- **Empfang → Status** nennt den Weg für ausgehende Mails; die Hinweise zum Einrichten nennen beide
  Wege.
- Datenbank-Migration 0006 legt die Tabelle `dmarc_failure_reports` an.

## [0.6.1] – 2026-09-29

### Behoben

- Der Mailempfang nimmt Berichte an gültige Empfangsadressen wieder an. Die Prüfung bei `RCPT TO`
  griff nach dem Schließen der Datenbanksitzung auf die Adresse zu und scheiterte bei jeder gültigen
  Adresse.
- Unerwartete Fehler im Mailempfang beantwortet der Server mit `451`, der absendende Mailserver
  versucht es dann später erneut. Kann eine Mail nicht gespeichert werden, gilt dasselbe. Details
  stehen nur im Log.

## [0.6.0] – 2026-09-29

### Neu

- `POST /api/v1/domains` legt eine Domain samt Empfangsadresse an und liefert die Adresse für `rua`.
  Eine vorhandene Domain kommt mit derselben Adresse zurück, Domains aus Berichten ohne eigene Adresse
  bekommen eine. Das Token braucht mindestens die Rolle Manager.
- `python -m app.org_limits` zeigt und ändert die Grenzen einer Organisation.
- Domains mit Umlauten nimmt die Anwendung in beiden Schreibweisen an und speichert die xn--Form, die in
  den Berichten steht.

### Behoben

- Neue Organisationen, auch die aus der Ersteinrichtung, bekommen die Grenzen des Standardtarifs.
- „Neue Adresse“ auf der Domainseite legt die Adresse wieder an.

## [0.5.2] – 2026-09-29

### Geändert

- Das Abbild gibt es für amd64 und arm64, etwa für Server mit Ampere-Prozessoren wie Oracle A1.

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

[Unreleased]: https://github.com/brightcolor/dmarc-analyzer/compare/v0.6.1...HEAD
[0.6.1]: https://github.com/brightcolor/dmarc-analyzer/releases/tag/v0.6.1
[0.6.0]: https://github.com/brightcolor/dmarc-analyzer/releases/tag/v0.6.0
[0.5.2]: https://github.com/brightcolor/dmarc-analyzer/releases/tag/v0.5.2
[0.5.1]: https://github.com/brightcolor/dmarc-analyzer/releases/tag/v0.5.1
[0.5.0]: https://github.com/brightcolor/dmarc-analyzer/releases/tag/v0.5.0
[0.4.0]: https://github.com/brightcolor/dmarc-analyzer/releases/tag/v0.4.0
[0.3.0]: https://github.com/brightcolor/dmarc-analyzer/releases/tag/v0.3.0
[0.2.1]: https://github.com/brightcolor/dmarc-analyzer/releases/tag/v0.2.1
[0.2.0]: https://github.com/brightcolor/dmarc-analyzer/releases/tag/v0.2.0
[0.1.0]: https://github.com/brightcolor/dmarc-analyzer/commit/0ec5162
