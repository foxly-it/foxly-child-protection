# Migration von filter.foxly.de zu GitHub Pages

| | URL |
|---|---|
| **Bisher** | `https://filter.foxly.de/filterlist-child.txt` (Hetzner, CloudPanel, Cronjob 04:00) |
| **Neu** | `https://foxly-it.github.io/foxly-child-protection/filterlist-child.txt` |

Die bisherige URL wird erst abgeschaltet, wenn die neue Lösung in AdGuard Home nachweislich funktioniert (Schritt 8).

## Was sich inhaltlich ändert

Analyse des bisherigen Skripts `/usr/local/sbin/update-child-filter.sh`: Es lädt `https://raw.githubusercontent.com/0xDarkMatter/aegis-blocklist/master/grades/standard.txt` (reine Domainliste, 702 Einträge) und hängt per `awk` `$ctag=user_child` an. Dabei entsteht:

```
avg.com$ctag=user_child          # bisher
||avg.com^$ctag=user_child       # neu
```

Ohne `||` und `^` ist das in AdGuard Home keine Domainregel, sondern ein **Teilstring-Muster**. Geprüft mit der Filter-Engine von AdGuard Home (`urlfilter` v0.23.4):

| Anfrage (Client mit `user_child`) | bisher | neu |
|---|---|---|
| `avg.com`, `www.avg.com` | blockiert | blockiert |
| `bavg.com`, `navg.community`, `avg.com.evil.net` | **blockiert** (Fehltreffer) | nicht blockiert |
| beliebige Domain, Client ohne Tag | nicht blockiert | nicht blockiert |

Weitere Unterschiede:

- **700 statt 702 Regeln.** `venus.chub.ai` und `homixvpn.homix-technologies.com` entfallen, weil `||chub.ai^` und `||homix-technologies.com^` sie bereits abdecken. Die Wirkung ist identisch.
- Das alte Skript hätte Regeln mit fremdem Client-Tag (`$ctag=device_pc`) unverändert übernommen. Diese hätten dann für *alle* PCs gegolten. Regeln mit unbekannten Optionen hätte AdGuard Home komplett verworfen, und eine leere Quelle hätte eine Liste ohne Regeln veröffentlicht. All das wird jetzt abgefangen.
- Kommentare und der Aegis-Kopf bleiben erhalten, dazu kommen ein AdGuard-konformer Kopf (`! Title:`, `! Expires:`, `! Rules:`) und je Quelle URL, Lizenz und SHA-256.

## 1. GitHub-Repository einrichten

Erledigt: `foxly-it/foxly-child-protection`, öffentlich. Zum Nachbauen:

```bash
gh repo create foxly-it/foxly-child-protection --public --source . --push
```

Empfohlene Einstellungen (gesetzt):

- **Settings → Actions → General:** Workflow permissions *Read repository contents*, „Allow GitHub Actions to create and approve pull requests“ aus, Actions auf GitHub-eigene Actions beschränkt, Pinning per SHA erzwungen, Freigabe für Workflows aus Forks aller externen Beitragenden.
- **Settings → Rules → Rulesets:** `main` gegen Löschen und Force-Push geschützt.

## 2. GitHub Actions aktivieren

Actions sind in neuen Repositories aktiv. Die Workflows liegen unter `.github/workflows/`. Prüfen unter **Actions**: „Filterliste aktualisieren“ und „Validierung“ müssen gelistet sein. Der Zeitplan (täglich 04:00 Europe/Berlin) greift automatisch.

## 3. GitHub Pages konfigurieren

**Settings → Pages → Build and deployment → Source: GitHub Actions.** (Erledigt, per API: `gh api -X POST repos/foxly-it/foxly-child-protection/pages -f build_type=workflow`.)

Die Umgebung `github-pages` lässt Deployments nur vom Branch `main` zu (**Settings → Environments → github-pages**).

## 4. Erste Filterliste generieren

**Actions → Filterliste aktualisieren → Run workflow → Run workflow.** Nach etwa einer Minute sind alle drei Jobs (*build*, *deploy*, *archive*) grün. Die Zusammenfassung des Laufs zeigt Regelanzahl, Duplikate, redundante und verworfene Zeilen.

## 5. Veröffentlichte Datei testen

```bash
URL=https://foxly-it.github.io/foxly-child-protection/filterlist-child.txt
curl -sSfI "$URL" | grep -iE '^(HTTP|content-type)'     # HTTP/2 200, text/plain
curl -sSf "$URL" | head -10                               # Kopf mit ! Title: Foxly Child Protection
curl -sSf "$URL" | grep -c 'ctag=user_child'              # ~700
curl -sSf "$URL" | grep -vE '^(!|#|$)' | grep -vc 'ctag=user_child'   # 0
curl -sSf https://foxly-it.github.io/foxly-child-protection/status.json
```

## 6. Neue URL in AdGuard Home eintragen

Auf dem Raspberry Pi, erst nach Freigabe:

1. Vorher `AdGuardHome.yaml` sichern, z. B. `sudo cp /opt/AdGuardHome/AdGuardHome.yaml ~/AdGuardHome.yaml.bak` (Pfad je nach Installation).
2. **Filter → DNS-Sperrlisten → Sperrliste hinzufügen → Eigene Liste hinzufügen**
   Name `Foxly Child Protection`, URL wie oben.
3. Nach dem Hinzufügen muss die Liste mit ~700 Regeln und aktuellem Aktualisierungsdatum erscheinen.
4. Die bisherige Liste (`filter.foxly.de`) **deaktivieren, nicht löschen**. So ist ein Rückweg mit einem Klick möglich. Beide gleichzeitig aktiv zu lassen schadet nicht, die alte Liste würde aber weiter ihre Teilstring-Fehltreffer erzeugen.

## 7. Client-Tags prüfen

1. **Einstellungen → Client-Einstellungen:** Jedes Kindergerät ist ein persistenter Client mit Tag `user_child`, „Filterung aktivieren“ ist an. (Das war schon für die alte Liste nötig.)
2. **Filter → Benutzerdefinierte Filterregeln → Filterung überprüfen** (Client-Feld ab v0.107.58):

   | Domain | Client | Erwartung |
   |---|---|---|
   | `1337x.to` | IP eines Kindergeräts | blockiert durch `\|\|1337x.to^$ctag=user_child` (Liste *Foxly Child Protection*) |
   | `www.1337x.to` | IP eines Kindergeräts | blockiert (Subdomain) |
   | `1337x.to` | IP eines Erwachsenengeräts | nicht blockiert |
   | `bavg.com` | IP eines Kindergeräts | nicht blockiert (bisher Fehltreffer) |

   Per API:
   ```bash
   curl -su admin "http://ADGUARD-HOST/control/filtering/check_host?name=1337x.to&client=IP-DES-KINDERGERÄTS"
   ```
3. Praxistest auf einem Kindergerät: `nslookup 1337x.to` liefert `0.0.0.0` (Standard-Sperrmodus). Im **Abfrageprotokoll** erscheint die Anfrage als blockiert mit Regel `||1337x.to^$ctag=user_child` und Filter *Foxly Child Protection*. Gegenprobe auf einem Erwachsenengerät: normale Antwort.

## 8. Bisherige Hostinglösung abschalten

Voraussetzungen, alle erfüllt:

- [ ] Mindestens 3 aufeinanderfolgende geplante Läufe (04:00) grün unter **Actions**
- [ ] AdGuard Home zeigt die neue Liste mit aktuellem Datum (Update nach einem dieser Läufe)
- [ ] Tests aus Schritt 7 bestanden, Abfrageprotokoll der Kindergeräte unauffällig
- [ ] Keine weiteren Geräte oder Instanzen nutzen noch `filter.foxly.de` (Zugriffslog prüfen: `grep filterlist-child.txt` im nginx-Log der Site; nach der Umstellung dürfen keine Abrufe von der eigenen IP mehr kommen)

Danach in dieser Reihenfolge:

1. AdGuard Home: alte, deaktivierte Liste löschen.
2. Hetzner: Cronjob entfernen (`crontab -e` als root, Zeile `0 4 * * * /usr/local/sbin/update-child-filter.sh`), Skript archivieren.
3. Optional als Übergang: `filter.foxly.de/filterlist-child.txt` per `301` auf die neue URL umleiten. AdGuard Home folgt Weiterleitungen beim Filterabruf. CloudPanel → Site → Vhost:
   ```nginx
   location = /filterlist-child.txt { return 301 https://foxly-it.github.io/foxly-child-protection/filterlist-child.txt; }
   ```
4. Später: Site `filter.foxly.de` in CloudPanel und den DNS-Eintrag entfernen.

**Rückweg** jederzeit bis Schritt 8.2: alte Liste in AdGuard Home wieder aktivieren, neue deaktivieren.
