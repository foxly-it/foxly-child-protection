# Foxly Child Protection

[![Filterliste aktualisieren](https://github.com/foxly-it/foxly-child-protection/actions/workflows/update-filters.yml/badge.svg)](https://github.com/foxly-it/foxly-child-protection/actions/workflows/update-filters.yml)

DNS-Kinderschutzfilter für **AdGuard Home**. Jede Regel trägt das Client-Tag `$ctag=user_child` und wirkt deshalb **nur auf Kindergeräte**. Alle anderen Geräte im Netz bleiben unberührt. Die Liste wird täglich vollautomatisch von GitHub Actions erzeugt, geprüft und über GitHub Pages veröffentlicht. Ein eigener Server ist nicht nötig.

**Filterliste:**

```
https://foxly-it.github.io/foxly-child-protection/filterlist-child.txt
```

Projektseite mit Status: <https://foxly-it.github.io/foxly-child-protection/>

---

## Inhalt

- [Was ist Foxly Child Protection?](#was-ist-foxly-child-protection)
- [Funktionsweise](#funktionsweise)
- [Installation in AdGuard Home](#installation-in-adguard-home)
- [Client-Tags](#client-tags)
- [Eigene Regeln: Allowlist und Blocklist](#eigene-regeln-allowlist-und-blocklist)
- [Weitere Filterquellen](#weitere-filterquellen)
- [Automatische Aktualisierung](#automatische-aktualisierung)
- [Fehlerbehandlung](#fehlerbehandlung)
- [Sicherheit](#sicherheit)
- [Tests und lokale Ausführung](#tests-und-lokale-ausführung)
- [Einschränkungen](#einschränkungen)
- [Migration von filter.foxly.de](MIGRATION.md)

## Was ist Foxly Child Protection?

Eine DNS-Sperrliste für Kindergeräte im Heimnetz. Grundlage ist die [Aegis Blocklist](https://github.com/0xDarkMatter/aegis-blocklist) (Stufe *Standard*, CC0). Sie deckt u. a. VPN- und Proxy-Dienste zur Umgehung von Filtern, Glücksspiel, Erwachseneninhalte, KI-Erwachsenenangebote, Piraterie, Stalkerware, Cheating-Dienste und Incel/Manosphere-Seiten ab. Ergänzt wird sie durch eine eigene Blocklist und eine Allowlist.

Der Unterschied zu einer normalen Sperrliste: Durch `$ctag=user_child` greifen die Regeln ausschließlich für Clients, denen in AdGuard Home das Tag `user_child` zugewiesen ist. Die Liste kann also global aktiviert werden, ohne Erwachsene einzuschränken.

## Funktionsweise

```
config/sources.toml ─┐
                     ├─► Quellen abrufen (HTTPS, Größenlimit, Timeout, Wiederholungen)
                     ├─► Format pro Zeile erkennen: AdGuard-Regel · Domainliste · Hosts-Datei
                     ├─► Regeln prüfen, nicht sicher interpretierbare Zeilen verwerfen
config/blocklist.txt ┼─► eigene Domains ergänzen
config/allowlist.txt ┼─► Allowlist anwenden (hat Vorrang)
                     ├─► Duplikate und redundante Subdomains entfernen
                     ├─► $ctag=user_child ergänzen
                     ├─► Validierung (Python) + Prüfung mit der AdGuard-Home-Engine (Go)
                     └─► GitHub Pages ─► AdGuard Home ─► Kindergeräte
```

### Regelumwandlung

| Quelle | Ergebnis |
|---|---|
| `example.com` (Domainliste) | `\|\|example.com^$ctag=user_child` |
| `0.0.0.0 example.com` (Hosts) | `\|\|example.com^$ctag=user_child` |
| `\|\|example.com^` | `\|\|example.com^$ctag=user_child` |
| `\|\|example.com^$important` | `\|\|example.com^$important,ctag=user_child` |
| `\|\|example.com^$ctag=user_child` | bleibt unverändert |

`||domain^` sperrt die Domain und alle Subdomains, aber keine Domains, die den Namen nur enthalten. Reine Domain- und Hosts-Einträge werden bewusst so übernommen, weil eine Kinderschutzsperre für `example.com` auch `www.example.com` erfassen muss. Wer eine Quelle exakt übernehmen will (nur die Domain selbst, `|domain^`), setzt `include_subdomains = false`.

### Was verworfen wird

Konservativ gilt: Was nicht eindeutig als Domainsperre interpretierbar ist, wird **nicht** übernommen und im Workflow-Protokoll mit Grund und Beispielzeile gemeldet. Nichts wird stillschweigend in eine anders wirkende Regel umgeschrieben.

| Verworfen | Grund |
|---|---|
| `example.com$ctag=…` (ohne `\|\|`/`^`) | wirkt in AdGuard Home als Teilstring, z. B. auch auf `notexample.com.evil.net` |
| Regex `/…/`, Platzhalter `*`, `\|\|example.com` ohne `^` | Wirkung nicht sicher bestimmbar |
| `@@`-Ausnahmen aus externen Quellen | würden Sperren anderer Listen für Kinder aufheben |
| `$dnsrewrite`, `$client`, `$badfilter`, unbekannte Optionen | Umleitung, Fremdwirkung oder von AdGuard Home ignoriert |
| `$ctag` mit anderem Tag (`device_pc`, `~user_child`, …) | Regel gälte nicht nur für Kinder |
| Hosts-Einträge mit echter IP (`1.2.3.4 bank.example`) | Umleitung statt Sperre |
| kosmetische Regeln (`##`), ungültige Domains, Steuerzeichen | keine DNS-Regel bzw. defekt |

Erlaubte Optionen bleiben in Originalreihenfolge erhalten: `important`, `dnstype`, `denyallow` und ein vorhandenes `ctag=user_child`. Kommentare (`!` und `#`) der Quellen werden unverändert und an ihrer ursprünglichen Position übernommen.

### Duplikate

Gleiche Regeln aus verschiedenen Quellen oder Formaten (`example.com`, `||example.com^`, `0.0.0.0 example.com`) werden zusammengeführt. Optionen werden dabei unabhängig von der Reihenfolge verglichen. Zusätzlich entfallen Subdomain-Regeln, die eine übergeordnete `||domain^`-Regel bereits abdeckt (z. B. `venus.chub.ai` neben `chub.ai`).

## Installation in AdGuard Home

1. **Filter → DNS-Sperrlisten → Sperrliste hinzufügen → Eigene Liste hinzufügen**
2. Name: `Foxly Child Protection`, URL: `https://foxly-it.github.io/foxly-child-protection/filterlist-child.txt`
3. Speichern. Die Liste muss danach mit rund 700 Regeln erscheinen.
4. Empfohlen: **Einstellungen → Allgemeine Einstellungen → Filter-Aktualisierungsintervall: 24 Stunden** (oder kürzer)

Ohne Client mit dem Tag `user_child` blockiert die Liste nichts. Siehe nächster Abschnitt.

## Client-Tags

AdGuard Home trennt drei Dinge:

| Ebene | Wirkung |
|---|---|
| **Filterlisten** | global für alle Clients |
| **Client-Tags** | Merkmal eines *persistenten* Clients; Regeln mit `$ctag=…` gelten nur für Clients mit passendem Tag |
| **Client-Einstellungen** | pro Client: Filterung an/aus, Kindersicherung, Safe Search, gesperrte Dienste, eigene Upstreams |

Einrichtung:

1. **Einstellungen → Client-Einstellungen → Client hinzufügen**
2. Name vergeben, Kennung eintragen: feste IP-Adresse, MAC-Adresse (bei DHCP durch AdGuard Home) oder ClientID (DoH/DoT/DoQ).
3. Unter **Tags** `user_child` auswählen.
4. Sicherstellen, dass für den Client die **Filterung aktiviert** ist (bei „Globale Einstellungen verwenden“ automatisch).

Wichtig: Nur persistente Clients können Tags tragen. Automatisch erkannte Clients (Laufzeit-Clients) haben keine Tags, für sie greift die Liste nicht. Wechselt ein Kindergerät die IP (privates WLAN-MAC-Adress-Randomizing, neue DHCP-Lease), muss die Kennung stimmen. Feste DHCP-Reservierungen oder ClientIDs sind zuverlässiger.

**Prüfen:** **Filter → Benutzerdefinierte Filterregeln → Filterung überprüfen**, Domain aus der Liste (z. B. `1337x.to`) und als Client die IP des Kindergeräts eingeben. Ergebnis: blockiert durch `||1337x.to^$ctag=user_child`. Mit der IP eines Erwachsenengeräts darf die Domain nicht blockiert sein. Das Client-Feld gibt es ab AdGuard Home v0.107.58.

Die offizielle Beschreibung des Modifiers: [AdGuard DNS filtering syntax – ctag](https://adguard-dns.io/kb/general/dns-filtering-syntax/#ctag-modifier).

## Eigene Regeln: Allowlist und Blocklist

Beide Dateien: eine Domain pro Zeile, Kommentare mit `#`, ein Eintrag gilt immer auch für alle Subdomains. Ungültige Einträge (z. B. `*.example.com`, `||example.com^`, Umlaute ohne Punycode) brechen den Build mit Zeilennummer ab. Die bisherige Liste bleibt dann online. Doppelte Einträge werden mit Warnung zusammengeführt.

Änderungen direkt auf GitHub bearbeiten und committen genügt. Der Workflow startet automatisch und veröffentlicht die neue Liste nach wenigen Minuten. AdGuard Home übernimmt sie beim nächsten Filter-Update (oder sofort über „Nach Updates suchen“).

### `config/blocklist.txt`

```
# zusätzliche Sperren
example.com
example.net
```

Ergibt `||example.com^$ctag=user_child` usw.

### `config/allowlist.txt`

Die Allowlist hat Vorrang vor allen importierten Regeln und vor der Blocklist. Es gibt zwei bewusst getrennte Mechanismen:

| Eintrag | Wirkung |
|---|---|
| `schule.example` | **Entfernt** alle Sperrregeln dieser Liste für `schule.example` und seine Subdomains. Wirkt nur innerhalb dieser Liste. |
| `@@schule.example` | Entfernt wie oben **und erzeugt** die Ausnahmeregel `@@\|\|schule.example^$ctag=user_child`. Sie gibt die Domain für Kindergeräte auch dann frei, wenn eine *andere* in AdGuard Home aktive Liste sie sperrt. |

Sonderfall: Sperrt eine übergeordnete Regel die Domain weiter (Allowlist `lernen.example.org`, Quelle `||example.org^`), reicht Entfernen nicht. Dann wird automatisch eine Ausnahmeregel nur für `lernen.example.org` erzeugt und im Protokoll gemeldet. Trägt die übergeordnete Regel `$important`, erhält auch die Ausnahme `$important`, sonst würde sie nicht greifen.

Konflikte (Domain in Allow- und Blocklist) werden als Warnung gemeldet, die Allowlist gewinnt.

## Weitere Filterquellen

In `config/sources.toml` einen weiteren Block ergänzen. Eine Programmänderung ist nicht nötig:

```toml
[[sources]]
name = "Beispielliste"
url = "https://example.org/liste.txt"   # nur HTTPS
homepage = "https://example.org"
license = "CC-BY-4.0"
enabled = true
include_subdomains = true                # Domain-/Hosts-Einträge als ||domain^
min_rules = 1000                         # weniger = Quelle defekt, Build bricht ab
```

AdGuard-Regeln, Domainlisten und Hosts-Dateien werden pro Zeile automatisch erkannt, auch gemischt. Überschneidungen zwischen Quellen werden dedupliziert, die Herkunft bleibt über die Abschnittsköpfe in der Liste nachvollziehbar. Vor dem Aufnehmen einer Quelle deren Lizenz prüfen, weil die Liste öffentlich weiterverteilt wird.

## Automatische Aktualisierung

| Auslöser | Zeitpunkt |
|---|---|
| Zeitplan | täglich **04:00 Uhr deutscher Zeit** (`timezone: Europe/Berlin`, Sommer-/Winterzeit automatisch) |
| Push auf `main` | bei Änderungen an `config/`, `scripts/`, `site/`, `tests/`, `tools/` oder Workflows |
| manuell | **Actions → Filterliste aktualisieren → Run workflow** |

GitHub garantiert keine exakte Startzeit. Zur vollen Stunde ist die Last hoch, Läufe können sich um Minuten bis selten über eine Stunde verzögern oder in Extremfällen ausfallen. Für eine Filterliste, die AdGuard Home ohnehin nur periodisch abruft, ist das unkritisch. Der nächste Lauf holt alles nach.

Ablauf (`update-filters.yml`):

1. **build** (`validate.yml`, nur Leserechte): Unit-Tests → Liste erzeugen → Validierung → Prüfung mit der AdGuard-Home-Filter-Engine → Pages-Artefakt
2. **deploy** (nur `pages: write`): Veröffentlichung auf GitHub Pages
3. **archive** (nur `contents: write`): Ablage unter [`filters/filterlist-child.txt`](filters/filterlist-child.txt), aber nur wenn sich Regeln geändert haben. So bleibt jede inhaltliche Änderung in der Git-Historie nachvollziehbar.

GitHub deaktiviert Zeitpläne in öffentlichen Repositories nach 60 Tagen ohne Aktivität. Ändert sich die Quelle länger nicht (Aegis wurde zuletzt im Mai 2026 aktualisiert), legt der Workflow nach 45 Tagen einen Keepalive-Commit an. Falls der Zeitplan dennoch deaktiviert wurde: **Actions → Filterliste aktualisieren → Enable workflow**.

## Fehlerbehandlung

Grundsatz: **Es wird nur veröffentlicht, was alle Prüfungen bestanden hat.** Bei jedem Fehler bricht der Workflow vor dem Deployment ab. Die zuletzt veröffentlichte Liste bleibt unverändert online, AdGuard Home behält sie.

| Situation | Verhalten |
|---|---|
| Quelle nicht erreichbar, Timeout, HTTP-Fehler | 3 Versuche (bei 5xx/429/Netzwerkfehler), danach Abbruch |
| Quelle leer, abgeschnitten, Format geändert | Abbruch, wenn weniger gültige Regeln als `min_rules` |
| Quelle liefert HTML (Fehlerseite) oder kein UTF-8 | Abbruch |
| Quelle größer als `max_download_bytes` | Abbruch |
| Liste schrumpft um mehr als `max_shrink_percent` (30 %) | Abbruch; bei Absicht manuell mit `allow_shrink` starten |
| einzelne ungültige oder unsichere Zeilen | verworfen, als Warnung mit Beispiel im Protokoll |
| ungültiger Eintrag in Allow-/Blocklist | Abbruch mit Datei und Zeilennummer |
| Validierung oder Engine-Prüfung schlägt fehl | Abbruch |

Fehlgeschlagene Läufe meldet GitHub per E-Mail an den Repository-Inhaber. Der Status-Badge oben und auf der Projektseite zeigt den letzten Lauf. `status.json` enthält Zeitpunkt, Regelanzahl und SHA-256 jeder Quelle und eignet sich für Monitoring, z. B. ein Uptime-Kuma-Check auf das Alter von `generated`.

## Sicherheit

- Keine Zugangsdaten, Tokens, IP-Adressen oder personenbezogenen Daten im Repository. Der Workflow nutzt ausschließlich das automatische, kurzlebige `GITHUB_TOKEN`.
- `permissions: {}` global, jeder Job erhält nur die Rechte, die er braucht. Der Job, der externe Daten verarbeitet, hat nur Leserechte und keine gespeicherten Git-Zugangsdaten.
- Alle Actions sind per Commit-SHA gepinnt und stammen von GitHub (`actions/*`). Dependabot schlägt monatlich gebündelte Updates vor, ein Test erzwingt das Pinning.
- Heruntergeladene Inhalte werden nie ausgeführt, nur als Text geparst. Nur HTTPS, auch bei Weiterleitungen, mit Größenlimit, Timeout und strenger Prüfung jeder Zeile.
- Ausnahmeregeln, Umleitungen (`dnsrewrite`, Hosts mit echter IP) und Optionen mit Wirkung auf andere Listen (`badfilter`) aus externen Quellen werden nicht übernommen. Eine manipulierte Quelle kann damit Sperren hinzufügen, aber keine Freigaben erzwingen oder Anfragen umleiten.
- Steuerzeichen aus Quellen werden maskiert, bevor sie im Protokoll erscheinen, damit keine Workflow-Befehle eingeschleust werden können.
- Workflow-Änderungen werden im Pull Request automatisch geprüft (`validate.yml`, nur Leserechte, kein `pull_request_target`).

## Tests und lokale Ausführung

Voraussetzung: Python ≥ 3.11 (nur Standardbibliothek), für die Engine-Prüfung Go.

```bash
python3 -m unittest discover -s tests -v          # Unit-Tests
python3 scripts/update_filters.py --out public    # Liste erzeugen
python3 scripts/validate_filters.py public/filterlist-child.txt
cd tools/engine-check && go run . ../../public/filterlist-child.txt
```

Die Engine-Prüfung nutzt [`urlfilter`](https://github.com/AdguardTeam/urlfilter) in derselben Version wie das aktuelle AdGuard-Home-Release (derzeit v0.107.79 → urlfilter v0.23.4). Nach einem AdGuard-Home-Update mit neuer urlfilter-Version angleichen: `cd tools/engine-check && go get github.com/AdguardTeam/urlfilter@vX.Y.Z && go mod tidy`. Sie stellt sicher, dass jede Regel von AdGuard Home akzeptiert wird, Sperren für `user_child` greifen (inkl. Subdomains), Clients ohne Tag nie blockiert werden und kein Teilstring-Treffer entsteht.

```
foxly-child-protection/
├── .github/
│   ├── workflows/update-filters.yml   Zeitplan, Deployment, Archiv
│   ├── workflows/validate.yml         Tests, Build, Prüfung (auch für PRs)
│   └── dependabot.yml
├── config/
│   ├── sources.toml                   Quellen und Einstellungen
│   ├── allowlist.txt
│   └── blocklist.txt
├── filters/filterlist-child.txt       zuletzt veröffentlichte Liste (vom Workflow gepflegt)
├── scripts/update_filters.py          Erzeugung
├── scripts/validate_filters.py        Validierung
├── site/index.html                    Vorlage der Projektseite
├── tests/test_filters.py
└── tools/engine-check/                Prüfung mit der AdGuard-Home-Engine
```

`sources.toml` statt YAML, weil Python TOML ohne Zusatzpaket lesen kann.

## Einschränkungen

**DNS-Filterung ist kein vollständiger Jugendschutz.** Sie ist ein sinnvoller Baustein, ersetzt aber weder Gerätebeschränkungen noch Begleitung und Gespräche.

- **Umgehung:** VPNs, Proxys, Tor, verschlüsseltes DNS im Browser oder Betriebssystem (DoH/DoT), fest eingetragene fremde DNS-Server und mobile Daten umgehen AdGuard Home vollständig. Die Liste sperrt bekannte VPN- und DoH-Anbieter, aber nie alle. Ergänzend sinnvoll: DNS-Umleitung bzw. Sperre von Port 53/853 für fremde Server in der Firewall, Gerätebeschränkungen (iOS Bildschirmzeit, Google Family Link, Microsoft Family Safety), siehe auch die [Device-Lockdown-Anleitungen von Aegis](https://github.com/0xDarkMatter/aegis-blocklist).
- **Granularität:** DNS sieht nur Domainnamen, keine Inhalte. Einzelne Seiten, Videos oder Chats auf erlaubten Plattformen (YouTube, Discord, soziale Netzwerke) lassen sich nicht filtern. Dafür Safe Search und gesperrte Dienste in den Client-Einstellungen nutzen.
- **Vollständigkeit:** Keine Liste kennt alle problematischen Domains. Neue Angebote entstehen täglich.
- **Fehlsperren:** Eine Sperre kann legitime Dienste treffen. Dafür gibt es die Allowlist.
- **Client-Erkennung:** Die Liste wirkt nur, wenn AdGuard Home das Kindergerät als persistenten Client mit Tag erkennt (siehe [Client-Tags](#client-tags)).
- **Zeitplan:** GitHub-Zeitpläne sind nicht minutengenau, siehe [Automatische Aktualisierung](#automatische-aktualisierung).

## Lizenz

Code: [MIT](LICENSE). Die erzeugte Liste enthält Daten der jeweiligen Quellen unter deren Lizenz, Aegis Blocklist: [CC0 1.0](https://github.com/0xDarkMatter/aegis-blocklist/blob/master/LICENSE).
