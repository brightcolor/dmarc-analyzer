# DMARC Analyzer

Selbst gehostete Auswertung von DMARC-Sammelberichten für mehrere Organisationen. Die Anwendung
nimmt Berichte über einen eigenen Mailempfang an, wertet sie aus und zeigt in einer
Weboberfläche, wer im Namen deiner Domains Mails verschickt, was DMARC besteht und was nicht.

Sie liest beide Fassungen von DMARC: RFC 7489 von 2015 und DMARCbis von 2026 (RFC 9989 und
RFC 9990). Jeder Bericht zeigt, in welchem Format er ankam und woran das erkannt wurde.

---

## Funktionen

- **Eigener Mailempfang** mit aiosmtpd: nimmt nur Mails an die Empfangsadressen der Organisationen
  an, lehnt Unbekannte schon bei `RCPT TO` ab und leitet nichts weiter. Mit eigenem Zertifikat bietet
  er STARTTLS an.
- **Beide Berichtsformate**: RFC 7489 und RFC 9990, mit und ohne Namespace. Die Auswertung kennt
  den Testmodus `t`, die Policy `np` für nicht existierende Subdomains, `pct` und die Behandlung
  `pass`.
- **Fehlerberichte (`ruf`)** im Abuse Reporting Format: Quelle, gescheiterte Prüfung, Zustellung und
  die Kopfzeilen der gemeldeten Mail. Den Inhalt der Mail speichert die Anwendung nie, die Berichte
  verschwinden nach einer eigenen, kurzen Frist.
- **TLS-Berichte (TLS-RPT, RFC 8460)**: Mailserver wie Google und Microsoft melden einmal am Tag, wie
  viele Verbindungen zu deinen Mailservern verschlüsselt zustande kamen und woran die übrigen
  scheiterten, etwa an einem abgelaufenen Zertifikat oder einer MTA-STS-Richtlinie, die sich nicht
  abrufen ließ.
- **Empfehlungen je Domain**, etwa bereit für `p=quarantine` oder `p=reject`, `pct=0` ohne `t=y`,
  unbekannte Quellen und fehlende Berichte. Alle Schwellen sind einstellbar.
- **DNS-Vorschlag** für den DMARC-Eintrag, der für Empfänger beider Standards passt, für den
  Zustimmungseintrag unter `_report._dmarc` und für den TLS-Berichtseintrag unter `_smtp._tls`.
- **DNS-Prüfung je Domain**: DMARC, Zustimmung der Empfangsdomain, SPF samt Zahl der DNS-Abfragen, die
  DKIM-Schlüssel der Selektoren aus den Berichten, Mailserver und TLS-Berichte, mit Ampel, dem richtigen
  Wert zum Kopieren und einem Alarm, wenn ein Eintrag fehlt oder falsch ist.
- **Absender mit Namen**: Jede IP-Adresse wird einem Dienst zugeordnet, etwa Google, Microsoft 365,
  Amazon SES, Mailchimp oder IONOS. Ein Klick gibt einen Dienst mit allen seinen Adressen frei, auch mit
  künftigen.
- **Alarme** für 15 Auffälligkeiten, von neuen unbekannten Quellen über steigende Fehlerquoten,
  scheiternde TLS-Verbindungen und fehlerhafte DNS-Einträge bis zu ausbleibenden Berichten. Benachrichtigung per E-Mail, Webhook, ntfy oder Slack und Mattermost.
- **Mailversand** über einen SMTP-Server oder die HTTP-API von Postal, auch von Hosts, deren Anbieter
  ausgehenden Port 25 sperrt.
- **Weitere Empfänger je Domain** für ihre Alarme und einen eigenen Wochenbericht, der nur diese
  Domain zeigt, etwa für Agenturen oder Kunden.
- **Wochenbericht** per Mail mit Bestehensquote, Quellen mit Fehlern, neuen Quellen, offenen Alarmen
  und Empfehlungen.
- **Aufräumen nach Frist**: alte Berichte, Importe, Rohmails und abgelehnte Zustellversuche verschwinden
  nach den eingestellten Tagen.
- **Mehrere Organisationen** mit getrennten Daten, abgestuften Rollen und API-Tokens.
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

### Grenzen einer Organisation

Neue Organisationen starten mit den Grenzen des Standardtarifs (`DEFAULT_PLAN_*`). Anzeigen und ändern
kann sie der Betreiber:

```bash
docker compose exec web python -m app.org_limits
docker compose exec web python -m app.org_limits <kennung> --max-domains 500
```

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

   Für Fehlerberichte kommt dieselbe Adresse zusätzlich in `ruf`, dazu `fo=1`, damit Empfänger schon
   melden, wenn SPF oder DKIM scheitert. Der Vorschlag auf der Domainseite enthält beides, solange
   `DMARC_SUGGEST_FAILURE_REPORTS` und `FAILURE_REPORTS_ENABLED` an sind:

   ```
   _dmarc.example.com.  TXT  "v=DMARC1; p=none; rua=mailto:dom-example-com-abc123@reports.example.com; ruf=mailto:dom-example-com-abc123@reports.example.com; fo=1"
   ```

3. **Zustimmung der Empfangsdomain.** Liegt die Empfangsadresse auf einer anderen Domain als die
   ausgewertete, stellen Empfänger Berichte erst zu, wenn die Empfangsdomain zustimmt. Diesen
   Eintrag setzt, wer die Zone der Empfangsdomain verwaltet:

   ```
   example.com._report._dmarc.reports.example.com.  TXT  "v=DMARC1"
   ```

   Ein Platzhaltereintrag `*._report._dmarc.reports.example.com` stimmt für alle Domains zu.

4. **TLS-Berichte je Domain**, für Domains, die selbst Mails empfangen. Dieselbe Empfangsadresse
   kommt in einen TXT-Eintrag unter `_smtp._tls`; die Domainseite zeigt ihn zum Kopieren:

   ```
   _smtp._tls.example.com.  TXT  "v=TLSRPTv1; rua=mailto:dom-example-com-abc123@reports.example.com"
   ```

   Eine Zustimmung der Empfangsdomain wie bei DMARC braucht dieser Eintrag nicht.

Ob alles steht, zeigt die [DNS-Prüfung](#dns-prüfung) auf jeder Domainseite.

---

## DNS-Prüfung

Die Anwendung prüft für jede aktive Domain, ob die DNS-Einträge stehen, die DMARC und die Berichte
brauchen. Das Ergebnis steht auf der Domainseite unter **DNS-Prüfung**, mit Ampel je Prüfung, dem
gefundenen Wert und, wo etwas fehlt oder falsch ist, dem richtigen Wert zum Kopieren.

| Prüfung | In Ordnung, wenn … |
|---|---|
| DMARC-Eintrag | unter `_dmarc.<domain>` genau ein Eintrag steht, der mit `v=DMARC1` beginnt; eine Subdomain ohne eigenen Eintrag nutzt den der Organisationsdomain |
| Policy und Aufbau | `p` gültig ist und alle übrigen Angaben gültige Werte haben; `p=none`, `pct` unter 100 und `t=y` erscheinen als Hinweis |
| Sammelberichte (`rua`) | `rua` eine aktive Empfangsadresse der Organisation nennt |
| Fehlerberichte (`ruf`) | `ruf` die Empfangsadresse nennt, mit `fo=1` (Warnung, solange `DMARC_SUGGEST_FAILURE_REPORTS` an ist) |
| Zustimmung der Empfangsdomain | `<domain>._report._dmarc.<Empfangsdomain>` mit `v=DMARC1` antwortet, wenn die Adresse unter einer anderen Domain liegt |
| SPF | genau ein Eintrag steht, mit höchstens 10 DNS-Abfragen samt aller `include` (RFC 7208), ohne `+all`, ohne `ptr` |
| DKIM | für jeden Selektor, der in den Berichten der letzten `DNS_CHECK_DKIM_DAYS` Tage bestanden hat, ein Schlüssel im DNS steht, RSA mit mindestens 1024 Bit (RFC 8301) |
| Mailserver (MX) | jeder MX-Host eine IP-Adresse hat; ohne MX oder mit Null-MX gilt die Domain als ohne Mailempfang |
| TLS-Berichte | eine Domain mit Mailempfang unter `_smtp._tls` genau einen Eintrag hat, dessen `rua` die Empfangsadresse nennt |

Den richtigen Wert baut die Anwendung aus dem Eintrag, der gerade im DNS steht: Policy, Ausrichtung
und alle übrigen Angaben bleiben, dazu kommt die Empfangsadresse. Andere Empfänger in `rua` bleiben
stehen.

- Der Zeitplaner prüft jede aktive Domain nach `DNS_CHECK_MAX_AGE_SECONDS` (Vorgabe ein Tag) erneut,
  neue Domains zuerst, je Lauf höchstens `DNS_CHECK_BATCH_SIZE` Domains, `DNS_CHECK_WORKERS` gleichzeitig.
- **Jetzt prüfen** auf der Domainseite prüft sofort, ab der Rolle Analyst.
- Die Domainliste zeigt den Stand jeder Domain und filtert nach „Fehler“, „Warnungen“ oder „noch nicht
  geprüft“; die Übersicht nennt die Zahl der Domains mit Fehlern.
- Die Alarmart „DNS-Einträge fehlerhaft“ meldet jede Domain mit einem Fehler; Hinweise und Warnungen
  lösen keinen Alarm aus.
- Antwortet ein DNS-Server nicht, bleibt die betroffene Prüfung offen („keine Antwort“), und der nächste
  Lauf versucht es erneut.

Die Abfragen gehen an `DNS_NAMESERVERS` oder, wenn leer, an die DNS-Server des Systems. Hält der
Resolver des Hosters ein „gibt es nicht“ lange fest, etwa direkt nach dem Anlegen eines Eintrags,
helfen öffentliche Resolver wie `DNS_NAMESERVERS=1.1.1.1,9.9.9.9`.

---

## Verschlüsselter Mailempfang (STARTTLS)

Mit einem Zertifikat für die Empfangsdomain bietet der Mailempfang STARTTLS an, so wie Mailserver es
auf Port 25 erwarten: Die Verbindung beginnt unverschlüsselt und wechselt nach dem `EHLO`. Absender
ohne TLS liefern weiter.

```
SMTP_INBOUND_TLS_ENABLED=true
SMTP_INBOUND_TLS_CERT_PATH=/certs/reports.example.com.crt
SMTP_INBOUND_TLS_KEY_PATH=/certs/reports.example.com.key
SMTP_INBOUND_TLS_MIN_VERSION=TLSv1.2
```

Die Pfade gelten im Container. Das Verzeichnis kommt schreibgeschützt in den Dienst `smtp`, etwa in
einer `compose.override.yaml`:

```yaml
services:
  smtp:
    volumes:
      - /pfad/zu/den/zertifikaten:/certs:ro
    group_add:
      - "1000"   # Gruppe, die den Schlüssel lesen darf
```

Der Container läuft als Benutzer `1001`; er braucht Leserecht auf Zertifikat und Schlüssel. Lässt sich
das Zertifikat nicht laden, läuft der Empfang ohne STARTTLS weiter und das Log nennt Pfad und Grund.
Ein erneuertes Zertifikat gilt nach einem Neustart des Dienstes (`docker compose restart smtp`); dieser
Befehl gehört in den Ablauf, der das Zertifikat erneuert. Prüfen lässt sich der Empfang so:

```bash
openssl s_client -starttls smtp -connect reports.example.com:25 -servername reports.example.com
```

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

## Fehlerberichte

Fehlerberichte (RFC 5965 und RFC 6591, für DMARCbis RFC 9991) melden einzelne Mails, die an DMARC,
DKIM oder SPF gescheitert sind. Empfänger schicken sie an die Adresse in `ruf`; die Anwendung erkennt
sie an der Empfangsadresse der Domain und legt sie unter **Berichte → Fehlerberichte** ab. Jeder
Bericht zeigt Quelle, gescheiterte Prüfung, ob SPF oder DKIM zur Domain passen, was der Empfänger mit
der Mail gemacht hat, das Prüfergebnis des Empfängers und die Kopfzeilen der gemeldeten Mail.

Fehlerberichte enthalten personenbezogene Daten, etwa Empfänger und Betreff. Deshalb gilt:

- Den Inhalt der gemeldeten Mail speichert die Anwendung nie, auch keine Anhänge daraus.
- Die Kopfzeilen speichert sie nur mit `FAILURE_REPORT_STORE_HEADERS=true` (Vorgabe) und höchstens
  `FAILURE_REPORT_MAX_HEADER_BYTES` Bytes.
- Nach `FAILURE_REPORT_RETENTION_DAYS` Tagen (Vorgabe 30) löscht der Zeitplaner jeden Bericht; bewahrt
  die Organisation Berichte kürzer auf, gilt ihre Frist.
- Ab der Rolle Manager lässt sich ein Bericht sofort löschen; das steht im Audit-Log.

Viele große Anbieter verschicken keine Fehlerberichte. Mit `FAILURE_REPORTS_ENABLED=false` vermerkt die
Anwendung solche Mails nur unter **Empfang → Eingegangene Mails**.

---

## TLS-Berichte

TLS-Berichte (SMTP TLS Reporting, RFC 8460) kommen von den Mailservern, die Mails an deine Domains
zustellen. Einmal am Tag melden sie, wie viele Verbindungen zu deinen Mailservern mit TLS zustande
kamen, nach welcher Richtlinie sie geprüft haben (MTA-STS, DANE oder ohne Richtlinie) und woran
gescheiterte Verbindungen lagen. Die Berichte kommen als JSON-Datei an die Adresse im Eintrag
`_smtp._tls`; die Anwendung erkennt sie am Berichtstyp `tlsrpt`, an den Medientypen
`application/tlsrpt+gzip` und `application/tlsrpt+json` oder an einer lesbaren `.json`-Datei.

- **Berichte → TLS-Berichte** listet alle Berichte mit Domain, Absender, Verbindungen und Anteil der
  gescheiterten; ein Filter zeigt nur Berichte mit Fehlern.
- Die Einzelansicht zeigt je Richtlinie die Gründe, etwa „Zertifikat abgelaufen“, „STARTTLS fehlt“ oder
  „MTA-STS-Richtlinie nicht abrufbar“, mit einem Hinweis, was zu tun ist, dazu Absender-IP, Mailserver
  und Fehlercode.
- Die Domainseite fasst die Berichte der letzten `UI_CHART_DAYS` Tage zusammen und nennt den häufigsten
  Grund.
- Die Alarmart „TLS-Verbindungen scheitern“ schlägt an, wenn der Anteil gescheiterter Verbindungen die
  Schwelle erreicht (Vorgabe `ALERT_DEFAULT_TLS_FAIL_RATE`, 5 %). Weil Absender einmal am Tag berichten,
  passt ein Zeitraum ab 1440 Minuten.
- Ein Bericht, der doppelt ankommt, bleibt einmal gespeichert. Mehr als `TLS_REPORT_MAX_POLICIES`
  Richtlinien lehnt die Anwendung ab; von den Fehlerangaben behält sie die
  `TLS_REPORT_MAX_FAILURE_DETAILS` mit den meisten Verbindungen, die Summen bleiben vollständig.
- TLS-Berichte folgen der Aufbewahrung der Organisation wie die DMARC-Berichte.

Mit `TLS_REPORTS_ENABLED=false` behandelt die Anwendung solche Mails wie jede andere und vermerkt unter
**Empfang → Eingegangene Mails**, dass sich der Anhang nicht importieren ließ.

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
| TLS-Verbindungen scheitern | der Anteil gescheiterter TLS-Verbindungen laut TLS-Berichten die Schwelle erreicht | `ALERT_DEFAULT_TLS_FAIL_RATE` |
| Versandmenge steigt oder fällt plötzlich | die Menge vom Durchschnitt der Zeiträume davor abweicht | `ALERT_DEFAULT_VOLUME_SPIKE`, `ALERT_DEFAULT_VOLUME_DROP` |
| Berichte bleiben aus | im Zeitraum kein Bericht ankam | – |
| DNS-Einträge fehlerhaft | die DNS-Prüfung einer Domain einen Fehler zeigt | – |
| Import fehlgeschlagen | Dateien sich nicht importieren ließen | `ALERT_DEFAULT_IMPORT_FAILURES` |
| Domain bereit für eine strengere Policy | die Zahlen `p=quarantine` oder `p=reject` tragen | – |
| Viele Mails an unbekannte Adressen | der Mailempfang viele Mails an unbekannte Adressen ablehnt (nur Betreiber) | `ALERT_DEFAULT_INVALID_RECIPIENTS` |
| Grenze für eingehende Mails erreicht | Absender die Mailgrenze treffen (nur Betreiber) | `ALERT_DEFAULT_RATE_LIMIT_HITS` |

Eine Regel für alle Domains prüft jede aktive Domain einzeln: Jeder Alarm nennt seine Domain und geht
auch an deren weitere Empfänger. „Berichte bleiben aus“ meldet dabei nur Domains, die schon einmal einen
Bericht hatten; geparkte Domains ohne Mailversand bleiben still. Gilt eine Regel für eine bestimmte
Domain, meldet sie auch, wenn dort noch nie ein Bericht ankam.

Eine Regel meldet denselben Befund erst wieder, wenn der vorige Alarm erledigt ist, und wartet danach
ihre Pause ab. Befund und Pause gelten je Domain und Quelle: Scheitert eine zweite Domain, kommt ihr
Alarm sofort. So kommt auch eine neue Quelle genau einmal.

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

Alarme per E-Mail sammelt die Anwendung `NOTIFICATION_EMAIL_BUNDLE_SECONDS` Sekunden lang (Vorgabe 900)
und schickt sie dann in einer Mail je Kanal oder Adresse, die wichtigsten zuerst. Ein einzelner Alarm
kommt in seiner eigenen Mail. Eine Sammelmail führt höchstens `NOTIFICATION_BUNDLE_MAX_ITEMS` Alarme
einzeln auf und nennt die übrigen als Zahl. Mit `0` geht jeder Alarm sofort einzeln raus. Webhook, ntfy
und Slack bekommen jeden Alarm sofort.

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

### Weitere Empfänger je Domain

Auf der Seite einer Domain trägt ein Manager unter **Weitere Empfänger** Adressen ein, die zusätzlich zu
den Kanälen und Empfängern der Organisation etwas bekommen, je Adresse wählbar:

- **Alarme**: jeder Alarm, der diese Domain betrifft, als eigene Mail. Alarme ohne Domain, etwa ein
  fehlgeschlagener Import, gehen nur an die Kanäle der Organisation.
- **Wochenbericht**: ein eigener Bericht zum selben Termin, der nur die Domains dieser Adresse zeigt.
  Steht eine Adresse bei mehreren Domains, bekommt sie eine Mail für alle zusammen. Der Schalter auf der
  Seite **Wochenbericht** gilt nur für die Empfänger der Organisation; eine neu eingetragene Adresse
  bekommt ihren ersten Bericht zum nächsten Termin.

Höchstens `DOMAIN_RECIPIENTS_MAX` Adressen je Domain (Vorgabe 20). Die Mails nennen den Grund, und wie
man sich austragen lässt. Eintragen, Ändern und Entfernen stehen im Audit-Log.

### Mailversand einrichten

E-Mail-Kanäle und der Wochenbericht brauchen einen Weg für ausgehende Mails: einen SMTP-Server oder
die API eines Postal-Servers. Trage ihn in die `.env` ein und starte den Web-Container neu.

Über SMTP:

```bash
MAIL_SMTP_HOST=smtp.example.com
MAIL_SMTP_PORT=587
MAIL_SMTP_SECURITY=starttls
MAIL_SMTP_USER=dmarc@example.com
MAIL_SMTP_PASSWORD=…
MAIL_FROM=DMARC Analyzer <dmarc@example.com>
```

Über die HTTP-API von [Postal](https://docs.postalserver.io/), etwa wenn der Anbieter des Hosts
ausgehenden Port 25 sperrt und Postal nur dort lauscht. Der Schlüssel ist ein Zugang vom Typ API am
Mailserver in Postal, die Domain von `MAIL_FROM` muss dort eingetragen und geprüft sein:

```bash
MAIL_BACKEND=postal
POSTAL_API_URL=https://postal.example.com
POSTAL_API_KEY=…
MAIL_FROM=DMARC Analyzer <dmarc@example.com>
```

Postal kennzeichnet die Mails mit `POSTAL_MESSAGE_TAG` (Vorgabe `dmarc-analyzer`).

Ob der Weg funktioniert, prüft `python -m app.mail_check` im Web-Container, ohne eine Mail zu
verschicken: Über SMTP meldet es sich an, bei Postal fragt es mit dem Schlüssel an.

Links, Logo und Schriften in den Mails zeigen auf `APP_URL`. Ob der Mailversand eingerichtet ist,
sieht der Betreiber unter **Empfang → Status**.

### Zeitplaner und Aufräumen

Der Zeitplaner läuft im Web-Container. Er prüft Regeln, verschickt Benachrichtigungen, sucht fällige
Wochenberichte, prüft das DNS der Domains und räumt auf. Jede Aufgabe läuft pro Takt genau einmal, auch mit mehreren
Web-Containern. Letzten Lauf und Ergebnis jeder Aufgabe zeigt **Empfang → Status** dem Betreiber.

Beim Aufräumen löscht die Anwendung Berichte, TLS-Berichte, Importe samt Dateien und empfangene Mails,
die älter sind als die Aufbewahrung der Organisation (`report_retention_days`, Vorgabe 365 Tage). Rohmails gehen
nach `SMTP_INBOUND_RAW_RETENTION_DAYS`, abgelehnte Zustellversuche nach
`SMTP_REJECTION_RETENTION_DAYS`, Fehlerberichte nach `FAILURE_REPORT_RETENTION_DAYS`. Ein Lauf löscht höchstens `RETENTION_BATCH_SIZE` Einträge je Art.

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
| `SMTP_INBOUND_TLS_*` | aus, TLS 1.2 | STARTTLS für den Mailempfang mit Zertifikat und Schlüssel |
| `DISPLAY_TIMEZONE` | `Europe/Berlin` | Zeitzone der Oberfläche |
| `UI_CHART_DAYS` | `30` | Tage im Verlaufsdiagramm |
| `RECOMMENDATION_*` | siehe `.env.example` | Schwellen der Empfehlungen |
| `ARCHIVE_MAX_*` | 20 MB, 50 MB, 50 Dateien | Grenzen für Anhänge und Archive |
| `SETUP_OPEN_PATHS` | `/static,/api,/health,…` | Pfade, die während der Ersteinrichtung offen bleiben |
| `MAIL_BACKEND` | `smtp` | Weg für ausgehende Mails: `smtp` oder `postal` |
| `MAIL_SMTP_*`, `MAIL_FROM` | Versand aus | SMTP-Server und Absender für Alarme und Wochenbericht |
| `POSTAL_API_URL`, `POSTAL_API_KEY`, `POSTAL_MESSAGE_TAG` | leer, leer, `dmarc-analyzer` | Versand über die Postal-API |
| `FAILURE_REPORTS_ENABLED`, `FAILURE_REPORT_*` | an, 30 Tage, Kopfzeilen bis 64 KB | Fehlerberichte |
| `DMARC_SUGGEST_FAILURE_REPORTS` | an | DNS-Vorschlag mit `ruf` und `fo=1` |
| `TLS_REPORTS_ENABLED`, `TLS_REPORT_*` | an, 100 Richtlinien, 1000 Fehlerangaben | TLS-Berichte |
| `DNS_CHECK_*` | an, täglich je Domain, 20 Domains je Lauf, 4 gleichzeitig, 4 s je Abfrage | DNS-Prüfung |
| `DOMAIN_RECIPIENTS_MAX` | 20 | weitere Empfänger je Domain |
| `DIGEST_*` | montags, 8 Uhr, 7 Tage | Termin und Inhalt des Wochenberichts |
| `ALERT_DEFAULT_*` | siehe `.env.example` | Schwellen für Regeln ohne eigenen Wert |
| `NOTIFICATION_*`, `NTFY_DEFAULT_URL` | 3 Versuche, `https://ntfy.sh` | Wiederholungen und Zeitlimits der Benachrichtigungen |
| `NOTIFICATION_EMAIL_BUNDLE_SECONDS`, `NOTIFICATION_BUNDLE_MAX_ITEMS` | 900, 50 | Sammelmails für Alarme |
| `SCHEDULER_ENABLED`, Takte `*_INTERVAL_SECONDS` | an | Zeitplaner im Web-Container |
| `RETENTION_*`, `SMTP_REJECTION_RETENTION_DAYS` | täglich, 30 Tage | Aufräumen |
| `SENDER_LOOKUP_*`, `SENDER_ASN_*` | an, jede Minute, 30 Tage | Zuordnung der Absender per DNS |
| `SENDER_CATALOG_PATH` | leer | eigener Absenderkatalog |
| `TRUSTED_PROXIES` | leer | Proxys, deren `X-Forwarded-For` zählt |
| `CSRF_TRUSTED_ORIGINS` | leer | weitere Adressen, von denen Formulare kommen dürfen |
| `LOGIN_*` | 10 je Konto, 20 je Adresse, 15 Minuten | Sperre gegen Raten |
| `NOTIFICATION_BLOCK_PRIVATE_TARGETS`, `NOTIFICATION_ALLOWED_INTERNAL_HOSTS` | an, leer | Schutz interner Dienste |
| `DEFAULT_PLAN_*` | 50 Domains, 20 Benutzer, 365 Tage | Grenzen des Standardtarifs für neue Organisationen |
| `DNS_NAMESERVERS` | die des Systems | DNS-Server für das Nachschlagen |
| `PUBLIC_SUFFIX_LIST_PATH` | mitgelieferte Liste | eigene Public Suffix List für die Organisationsdomain |

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
| GET | `/api/v1/domains` | Domains mit dem Stand ihrer DNS-Prüfung |
| GET | `/api/v1/domains/{id}/dns-check` | Ergebnis der letzten DNS-Prüfung |
| POST | `/api/v1/domains/{id}/dns-check` | DNS sofort prüfen, etwa nach einer Änderung (ab Rolle Analyst) |
| POST | `/api/v1/domains` | Domain anlegen, liefert ihre Empfangsadresse für `rua` (ab Rolle Manager) |
| GET | `/api/v1/domains/{id}/stats` | Kennzahlen einer Domain |
| GET | `/api/v1/reports` | Berichte mit Format (`report_format`, `format_evidence`) und Policy |
| GET | `/api/v1/failure-reports` | Fehlerberichte ohne die Kopfzeilen der gemeldeten Mail |
| GET | `/api/v1/tls-reports` | TLS-Berichte mit Richtlinien und Fehlerangaben |
| GET | `/api/v1/source-ips` | Versandquellen |
| GET | `/api/v1/alerts/events` | Alarme |
| POST | `/api/v1/alerts/events/{id}/acknowledge` | Alarm bestätigen |
| GET | `/api/v1/inbound-addresses` | Empfangsadressen |
| GET | `/api/v1/smtp/status` | Zustand des Mailempfangs |

Die vollständige Beschreibung steht unter `/api/docs`.

Eine Domain anlegen und die Adresse für den DMARC-Eintrag abholen:

```bash
curl -X POST -H "Authorization: Bearer <token>" -H "Content-Type: application/json" \
     -d '{"name": "example.org"}' https://dmarc.example.com/api/v1/domains
```

Die Antwort nennt `inbound_address` und `rua`. Gibt es die Domain schon, kommt sie mit Status 200 und
derselben Adresse zurück; Umlaute wandelt die Anwendung in die xn--Form, die auch in den Berichten steht.

---

## Rollen

Jedes Mitglied hat in seiner Organisation eine Rolle. Höhere Rollen dürfen alles, was die darunter
dürfen.

| Rolle | Darf |
|---|---|
| Lesezugriff | alles ansehen |
| Analyst | Berichte hochladen, IP-Adressen einstufen, Absender freigeben, Alarme als gesehen oder erledigt markieren |
| Manager | Domains anlegen und schalten, Alarmregeln anlegen und schalten |
| Administrator | Benachrichtigungskanäle, Wochenbericht, Mitglieder und API-Tokens verwalten |
| Betreiber | alle Organisationen, dazu Mailempfang, abgelehnte Empfänger und neue Organisationen |

Formulare, die eine Rolle nicht nutzen darf, blendet die Oberfläche aus; ein direkter Aufruf endet mit
einer Meldung, welche Rolle nötig ist. Ein API-Token handelt mit den Rechten des Kontos, das es angelegt
hat.

---

## Sicherheit

- **Formulare nur von der eigenen Seite.** Jede Änderung prüft `Origin` bzw. `Referer`; Formulare
  fremder Seiten lehnt die Anwendung ab. Weitere Adressen der Oberfläche nennt `CSRF_TRUSTED_ORIGINS`.
  Das Sitzungscookie trägt `SameSite=Lax`.
- **Sperre gegen Raten.** Nach `LOGIN_MAX_FAILURES_PER_ACCOUNT` Fehlversuchen für ein Konto oder
  `LOGIN_MAX_FAILURES_PER_IP` von einer Adresse innerhalb von `LOGIN_FAILURE_WINDOW_SECONDS` sperrt die
  Anmeldung für `LOGIN_LOCKOUT_SECONDS`. Dasselbe gilt für den Einrichtungscode.
- **Benachrichtigungen nur an öffentliche Adressen.** Webhook, ntfy und Slack dürfen nicht auf
  localhost, private oder reservierte Netze zeigen; die Anwendung prüft das beim Anlegen und vor jedem
  Versand. Interne Dienste wie ein eigener ntfy-Server kommen über `NOTIFICATION_ALLOWED_INTERNAL_HOSTS`
  dazu.
- **Client-Adresse hinter Proxys.** `X-Forwarded-For` zählt nur, wenn die Verbindung von einem Proxy
  aus `TRUSTED_PROXIES` kommt (Adressen oder Netze wie `172.16.0.0/12`).

Hinweise zum Melden von Schwachstellen stehen in [SECURITY.md](SECURITY.md).

## Lizenz

[MIT](LICENSE)
