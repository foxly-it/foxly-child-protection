# Migration vom Hetzner-Hosting zu GitHub Pages

| | |
|---|---|
| **Bisher** | `filter.foxly.de` auf Hetzner (CloudPanel), Cronjob 04:00 mit `/usr/local/sbin/update-child-filter.sh` |
| **Jetzt** | `filter.foxly.de` als Custom Domain von GitHub Pages, Erzeugung per GitHub Actions |
| **URL** | unverändert: `https://filter.foxly.de/filterlist-child.txt` |

Weil die URL gleich bleibt, muss in AdGuard Home nichts umgetragen werden. Die Umstellung erfolgt allein über DNS: Sobald `filter.foxly.de` auf GitHub zeigt, lädt AdGuard Home beim nächsten Filter-Update automatisch die neue Liste.

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

## 1. Repository, Actions und Pages (erledigt)

- Repository `foxly-it/foxly-child-protection`, öffentlich.
- **Settings → Actions → General:** Workflow permissions *Read repository contents*, „Allow GitHub Actions to create and approve pull requests“ aus, nur GitHub-eigene Actions erlaubt, SHA-Pinning erzwungen, Freigabe für Workflows aus Forks aller externen Beitragenden.
- **Settings → Rules → Rulesets:** `main` gegen Löschen und Force-Push geschützt.
- **Settings → Pages:** Source *GitHub Actions*, Custom Domain `filter.foxly.de`, *Enforce HTTPS* an. Die Umgebung `github-pages` erlaubt Deployments nur von `main`.
- Erster Lauf über **Actions → Filterliste aktualisieren → Run workflow**: alle drei Jobs (*build*, *deploy*, *archive*) grün.

## 2. DNS (erledigt)

```
filter.foxly.de.  60  IN  CNAME  foxly-it.github.io.
```

Der CAA-Eintrag von `foxly.de` (`issue "letsencrypt.org"`) erlaubt das Zertifikat, das GitHub für die Custom Domain ausstellt.

**Noch empfohlen:** Domain im GitHub-Konto verifizieren (**Profil → Settings → Pages → Add a domain** → `foxly.de`). GitHub nennt dann einen TXT-Eintrag `_github-pages-challenge-foxly-it.foxly.de`. Nach dem Eintragen und „Verify“ kann kein fremdes Repository `filter.foxly.de` übernehmen, auch nicht, falls Pages hier einmal abgeschaltet wird und der CNAME stehen bleibt.

## 3. Veröffentlichte Datei testen

```bash
URL=https://filter.foxly.de/filterlist-child.txt
curl -sSfI "$URL" | grep -iE '^(HTTP|content-type)'                  # HTTP/2 200, text/plain
curl -sSf "$URL" | head -8                                            # ! Title: Foxly Child Protection
curl -sSf "$URL" | grep -c '^||.*\$ctag=user_child$'                 # ~700
curl -sSf "$URL" | grep -vE '^(!|#|$)' | grep -vc 'ctag=user_child'   # 0
curl -sSf https://filter.foxly.de/status.json
```

Antwortet `curl` mit einem Zertifikatsfehler, hält ein Resolver noch den alten A-Eintrag (`128.140.49.48`) im Cache. Prüfen mit `dig +short filter.foxly.de`: richtig ist `foxly-it.github.io.` mit den IPs `185.199.108–111.153`. Der Cache läuft nach der alten TTL von selbst ab. Bei Unbound geht es sofort mit `unbound-control flush filter.foxly.de`, in AdGuard Home über **Einstellungen → DNS-Einstellungen → Cache leeren**.

## 4. AdGuard Home: neue Liste übernehmen

Wichtig: AdGuard Home löst die Filter-URL über sich selbst auf. Erst wenn sein Upstream (Unbound) den neuen CNAME liefert, kommt die neue Liste an.

1. **Filter → DNS-Sperrlisten → Nach Updates suchen** (oder bis zum nächsten automatischen Update warten).
2. Die Liste unter `https://filter.foxly.de/filterlist-child.txt` zeigt danach **700 Regeln** und das aktuelle Datum. Den Namen kann man auf *Foxly Child Protection* ändern.
3. Kontrolle des Formats: Im Abfrageprotokoll lauten die Regeln jetzt `||domain^$ctag=user_child`, nicht mehr `domain$ctag=user_child`.

## 5. Client-Tags prüfen

1. **Einstellungen → Client-Einstellungen:** Jedes Kindergerät ist ein persistenter Client mit Tag `user_child`, „Filterung aktivieren“ ist an.
2. **Filter → Benutzerdefinierte Filterregeln → Filterung überprüfen** (Client-Feld ab v0.107.58):

   | Domain | Client | Erwartung |
   |---|---|---|
   | `1337x.to` | IP eines Kindergeräts | blockiert durch `\|\|1337x.to^$ctag=user_child` |
   | `www.1337x.to` | IP eines Kindergeräts | blockiert (Subdomain) |
   | `1337x.to` | IP eines Erwachsenengeräts | nicht blockiert |
   | `bavg.com` | IP eines Kindergeräts | nicht blockiert (bisher Fehltreffer) |

   Per API:
   ```bash
   curl -su admin -G "http://ADGUARD-HOST/control/filtering/check_host" -d name=1337x.to -d client=IP-KINDERGERÄT
   ```
3. Praxistest auf einem Kindergerät: `nslookup 1337x.to` liefert `0.0.0.0` (Standard-Sperrmodus). Im **Abfrageprotokoll** erscheint die Anfrage als blockiert mit Regel `||1337x.to^$ctag=user_child`. Gegenprobe auf einem Erwachsenengerät: normale Antwort.

Lokal bereits verifiziert mit AdGuard Home v0.107.79 (gleiche Liste, Clients mit und ohne Tag, echte DNS-Abfragen und `check_host`).

## 6. Altes Hosting aufräumen

Die Site ist bereits offline. Sobald Schritt 4 und 5 erfolgreich waren und mindestens ein geplanter Lauf um 04:00 grün war:

1. Hetzner: Cronjob entfernen (`crontab -e` als root, Zeile `0 4 * * * /usr/local/sbin/update-child-filter.sh`), das Skript archivieren oder löschen.
2. CloudPanel: Site `filter.foxly.de` löschen, Zertifikat und Site-Benutzer `foxly-filter` entfallen damit.

**Rückweg** bis dahin: DNS wieder auf `A 128.140.49.48` setzen und die Site in CloudPanel aktivieren. Der Cronjob erzeugt die alte Liste weiterhin.
