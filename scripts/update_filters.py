#!/usr/bin/env python3
"""Erzeugt die Foxly-Child-Protection-Filterliste für AdGuard Home.

Ablauf: Quellen abrufen -> Zeilenformat erkennen (AdGuard-Regel, Domainliste,
Hosts-Datei) -> Regeln prüfen und mit $ctag versehen -> eigene Blocklist
ergänzen -> Allowlist anwenden -> Duplikate und redundante Subdomains
entfernen -> Filterliste, status.json und index.html schreiben.

Nicht sicher interpretierbare Zeilen werden verworfen und protokolliert, nie
stillschweigend in anders wirkende Regeln umgeschrieben. Schlägt ein Schritt
fehl, wird nichts geschrieben: die zuletzt veröffentlichte Liste bleibt gültig.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import ipaddress
import json
import os
import re
import shutil
import sys
import time
import tomllib
import urllib.error
import urllib.request
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape
from pathlib import Path
from string import Template
from zoneinfo import ZoneInfo

ROOT = Path(__file__).resolve().parent.parent
LIST_NAME = "filterlist-child.txt"
MAX_LINE = 1024
USER_AGENT = "foxly-child-protection (+https://github.com/foxly-it/foxly-child-protection)"

LABEL = r"(?!-)[a-z0-9_-]{1,63}(?<!-)"
DOMAIN_RE = re.compile(rf"(?:{LABEL}\.)+(?:[a-z]{{2,63}}|xn--[a-z0-9-]{{1,59}})")
# Einzige übernommene Adblock-Form: ||domain^ bzw. |domain^ mit optionalen Optionen.
ADBLOCK_RE = re.compile(r"(@@)?(\|\|?)([^|^$*/\s]+)\^(?:\$(.*))?")
DNSTYPE_RE = re.compile(r"~?[A-Za-z0-9]+(?:\|~?[A-Za-z0-9]+)*")
HOSTS_BLOCK_IPS = {"0.0.0.0", "127.0.0.1", "::", "::1"}
HOSTS_SKIP = {"localhost", "localhost.localdomain", "local", "broadcasthost",
              "ip6-localhost", "ip6-loopback", "0.0.0.0"}
SOURCE_KEYS = {"name", "url", "homepage", "license", "enabled", "include_subdomains", "min_rules"}


class Rejected(ValueError):
    """Eine einzelne Zeile ist nicht sicher interpretierbar."""


class BuildError(RuntimeError):
    """Fataler Fehler: es wird nichts veröffentlicht."""


@dataclass(frozen=True)
class Rule:
    domain: str
    mods: tuple[str, ...]      # Regeloptionen in Originalreihenfolge, inkl. ctag
    exact: bool = False        # |domain^ (ohne Subdomains) statt ||domain^
    exception: bool = False    # @@-Ausnahmeregel

    def __str__(self) -> str:
        return f"{'@@' * self.exception}{'|' if self.exact else '||'}{self.domain}^${','.join(self.mods)}"

    @property
    def key(self) -> tuple:
        return self.exception, self.exact, self.domain, frozenset(self.mods)

    @property
    def plain(self) -> bool:
        return all(m.startswith("ctag=") for m in self.mods)

    def covers(self, domain: str) -> bool:
        return domain == self.domain or (not self.exact and domain.endswith("." + self.domain))


@dataclass
class Section:
    title: str
    meta: list[str] = field(default_factory=list)
    entries: list = field(default_factory=list)          # Kommentare (str) und Regeln (Rule)
    rejected: Counter = field(default_factory=Counter)
    examples: dict = field(default_factory=dict)
    duplicates: int = 0
    redundant: int = 0
    allowlisted: int = 0
    stats: dict = field(default_factory=dict)

    @property
    def rules(self) -> list[Rule]:
        return [e for e in self.entries if isinstance(e, Rule)]


def notice(level: str, msg: str) -> None:
    """Meldung als GitHub-Annotation (in Actions) bzw. auf stderr (lokal)."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::{level}::{msg}", flush=True)
    else:
        print(f"{level.upper()}: {msg}", file=sys.stderr)


def is_domain(s: str) -> bool:
    return len(s) <= 253 and DOMAIN_RE.fullmatch(s) is not None


def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def parents(domain: str) -> list[str]:
    """a.b.example -> [a.b.example, b.example, example]"""
    parts = domain.split(".")
    return [".".join(parts[i:]) for i in range(len(parts))]


def tag_modifiers(raw: str | None, tag: str) -> tuple[str, ...]:
    """Prüft vorhandene Regeloptionen und hängt ctag an, ohne sie zu verändern."""
    mods = raw.split(",") if raw is not None else []
    names = [m.partition("=")[0] for m in mods]
    if len(set(names)) != len(names):
        raise Rejected("doppelte Regeloption")
    for mod in mods:
        name, eq, value = mod.partition("=")
        if name == "ctag":
            if value != tag:
                raise Rejected(f"abweichendes Client-Tag (Regel gälte nicht nur für {tag})")
        elif not ((name == "important" and not eq)
                  or (name == "dnstype" and DNSTYPE_RE.fullmatch(value))
                  or (name == "denyallow" and all(is_domain(d) for d in value.split("|")))):
            raise Rejected("nicht unterstützte Regeloption")
    return tuple(mods) if "ctag" in names else (*mods, f"ctag={tag}")


def parse_line(line: str, tag: str, subdomains: bool = True) -> list[Rule]:
    """Wandelt eine Regelzeile einer Quelle in Regeln um; Rejected bei Zweifeln."""
    if m := ADBLOCK_RE.fullmatch(line):
        exception, anchor, domain, raw = m.groups()
        if exception:
            raise Rejected("Ausnahmeregel (@@) aus externer Quelle")
        if not is_domain(domain.lower()):
            raise Rejected("ungültige Domain")
        return [Rule(domain.lower(), tag_modifiers(raw, tag), exact=anchor == "|")]
    parts = re.split(r"\s+#", line, maxsplit=1)[0].split()
    if len(parts) > 1 and is_ip(parts[0]):
        if parts[0] not in HOSTS_BLOCK_IPS:
            raise Rejected("Hosts-Eintrag mit Ziel-IP (Umleitung statt Sperre)")
        names = [n.lower() for n in parts[1:] if n.lower() not in HOSTS_SKIP]
    elif len(parts) == 1 and not re.search(r"[|^$*/@]", parts[0]):
        names = [parts[0].lower()]
    else:
        raise Rejected("nicht unterstützte Regelsyntax (Regex, Platzhalter, fehlender ||/^-Anker oder kosmetische Regel)")
    if not all(map(is_domain, names)):
        raise Rejected("ungültige Domain")
    return [Rule(n, (f"ctag={tag}",), exact=not subdomains) for n in names]


def parse_source(text: str, section: Section, tag: str, subdomains: bool) -> None:
    """Übernimmt Kommentare unverändert und Regeln in Originalreihenfolge."""
    for no, raw in enumerate(text.split("\n"), 1):
        line = raw.strip()
        if not line or (line[0] == "[" and line[-1] == "]"):     # leer oder [Adblock Plus 2.0]
            continue
        try:
            if len(line) > MAX_LINE or not line.replace("\t", " ").isprintable():
                raise Rejected("Zeile zu lang oder mit Steuerzeichen")
            if line[0] in "!#":
                section.entries.append(line)
            else:
                section.entries.extend(parse_line(line, tag, subdomains))
        except Rejected as e:
            section.rejected[str(e)] += 1
            # ascii() maskiert Steuerzeichen: Quelltext kann so keine Workflow-Befehle einschleusen.
            section.examples.setdefault(str(e), f"Zeile {no}: {ascii(line[:80])}".replace("`", "'"))


def decode(data: bytes) -> str:
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError as e:
        raise BuildError(f"kein gültiges UTF-8 (Byte {e.start}) – Datei beschädigt oder falsche Kodierung") from None
    if re.match(r"\s*<(!doctype|html)", text, re.I):
        raise BuildError("Antwort ist eine HTML-Seite statt einer Filterliste")
    return text


class _HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.startswith("https://"):
            raise urllib.error.URLError(f"Weiterleitung auf unsichere Adresse {newurl} abgelehnt")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def read_limited(resp, max_bytes: int) -> bytes:
    data = resp.read(max_bytes + 1)
    if len(data) > max_bytes:
        raise BuildError(f"größer als {max_bytes} Bytes – Download abgebrochen")
    return data


def fetch(url: str, max_bytes: int, timeout: float, retries: int = 3) -> bytes:
    """Lädt eine Quelle per HTTPS mit Größenlimit, Timeout und Wiederholungen."""
    if not url.startswith("https://"):
        raise BuildError("nur HTTPS-Quellen sind erlaubt")
    opener = urllib.request.build_opener(_HttpsOnlyRedirect)
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    for attempt in range(1, max(1, retries) + 1):
        try:
            with opener.open(request, timeout=timeout) as resp:
                return read_limited(resp, max_bytes)
        except urllib.error.HTTPError as e:
            error = f"HTTP {e.code} {e.reason}"
            if e.code < 500 and e.code != 429:
                break
        except (urllib.error.URLError, http.client.HTTPException, OSError) as e:
            error = str(getattr(e, "reason", e)) or type(e).__name__
        if attempt < retries:
            time.sleep(2 ** attempt)
    raise BuildError(f"Download fehlgeschlagen nach {attempt} Versuch(en): {error}")


def load_config(path: Path) -> dict:
    try:
        cfg = tomllib.loads(path.read_text("utf-8"))
        for key in ("title", "description", "homepage", "site_url", "list_url", "license"):
            cfg["project"][key]
        for key in ("client_tag", "max_download_bytes", "timeout_seconds", "retries", "max_shrink_percent"):
            cfg["settings"][key]
        for src in cfg["sources"]:
            src["name"], src["url"]
            if unknown := set(src) - SOURCE_KEYS:
                raise BuildError(f"Quelle '{src['name']}': unbekannte Einstellung {sorted(unknown)}")
    except (OSError, tomllib.TOMLDecodeError) as e:
        raise BuildError(f"Konfiguration {path} nicht lesbar: {e}") from None
    except KeyError as e:
        raise BuildError(f"Konfiguration {path}: Pflichtfeld {e} fehlt") from None
    return cfg


def read_domain_file(path: Path, allow_marker: bool = False) -> dict[str, bool]:
    """Liest allowlist/blocklist; liefert Domain -> explizite Ausnahme (@@)."""
    entries: dict[str, bool] = {}
    for no, raw in enumerate(path.read_text("utf-8").split("\n"), 1):
        line = raw.split("#", 1)[0].strip().lower()
        if not line:
            continue
        explicit = allow_marker and line.startswith("@@")
        domain = line[2:] if explicit else line
        if not is_domain(domain):
            raise BuildError(f"{path.name}, Zeile {no}: '{raw.strip()}' ist keine gültige Domain "
                             "(nur den Domainnamen eintragen, Umlaute als Punycode xn--…)")
        if domain in entries:
            notice("warning", f"{path.name}, Zeile {no}: {domain} ist doppelt eingetragen")
        entries[domain] = entries.get(domain, False) or explicit
    return entries


def count_rules(text: str) -> int:
    return sum(1 for line in text.split("\n") if line.strip() and line.lstrip()[0] not in "!#")


def build(cfg: dict, config_dir: Path, fetcher=fetch) -> list[Section]:
    settings = cfg["settings"]
    tag = settings["client_tag"]
    sections = []
    for src in cfg["sources"]:
        if not src.get("enabled", True):
            continue
        try:
            data = fetcher(src["url"], settings["max_download_bytes"], settings["timeout_seconds"], settings["retries"])
            text = decode(data)
        except BuildError as e:
            raise BuildError(f"Quelle '{src['name']}' ({src['url']}): {e}") from None
        sha256 = hashlib.sha256(data).hexdigest()
        section = Section(f"Quelle: {src['name']}", [f"URL: {src['url']}",
                          *([f"Lizenz: {src['license']}"] if "license" in src else []), f"SHA-256: {sha256}"])
        parse_source(text, section, tag, src.get("include_subdomains", True))
        section.stats = {"name": src["name"], "url": src["url"], "homepage": src.get("homepage", src["url"]),
                         "license": src.get("license", ""), "sha256": sha256,
                         "accepted": len(section.rules), "rejected": sum(section.rejected.values())}
        if len(section.rules) < src.get("min_rules", 1):
            raise BuildError(f"Quelle '{src['name']}': nur {len(section.rules)} gültige Regeln "
                             f"(Minimum {src.get('min_rules', 1)}) – Quelle leer, abgeschnitten oder Format geändert?")
        sections.append(section)
    if not sections:
        raise BuildError("keine aktive Filterquelle konfiguriert")

    blocked = read_domain_file(config_dir / "blocklist.txt")
    allowed = read_domain_file(config_dir / "allowlist.txt", allow_marker=True)
    sections.append(Section("Eigene Blocklist (config/blocklist.txt)",
                            entries=[Rule(d, (f"ctag={tag}",)) for d in blocked]))
    for domain in blocked:
        if hit := next((p for p in parents(domain) if p in allowed), None):
            notice("warning", f"Konflikt: {domain} steht in blocklist.txt, {hit} in allowlist.txt – Allowlist hat Vorrang")

    # 1. Allowlist hat Vorrang: Blockierregeln für erlaubte Domains und deren Subdomains entfernen.
    for section in sections:
        keep = []
        for e in section.entries:
            if isinstance(e, Rule) and any(p in allowed for p in parents(e.domain)):
                section.allowlisted += 1
            else:
                keep.append(e)
        section.entries = keep

    # 2. Duplikate und durch eine übergeordnete ||domain^-Regel redundante Regeln entfernen.
    seen: set = set()
    wildcard = {r.domain for s in sections for r in s.rules if r.plain and not r.exact}
    for section in sections:
        keep = []
        for e in section.entries:
            if isinstance(e, Rule):
                if e.key in seen:
                    section.duplicates += 1
                    continue
                seen.add(e.key)
                above = parents(e.domain)[0 if e.exact else 1:]
                if e.plain and any(p in wildcard for p in above):
                    section.redundant += 1
                    continue
            keep.append(e)
        section.entries = keep

    # 3. Ausnahmeregeln: explizit per @@ oder wenn eine übergeordnete Regel die Domain weiter sperrt.
    by_domain: dict[str, list[Rule]] = {}
    for r in (r for s in sections for r in s.rules):
        by_domain.setdefault(r.domain, []).append(r)
    exceptions = []
    for domain, explicit in allowed.items():
        covering = [r for p in parents(domain) for r in by_domain.get(p, ()) if r.covers(domain)]
        if covering and not explicit:
            notice("warning", f"Allowlist: {domain} wird weiterhin von {covering[0]} erfasst – Ausnahmeregel erzeugt")
        if explicit or covering:
            important = ("important",) if any("important" in r.mods for r in covering) else ()
            exceptions.append(Rule(domain, (*important, f"ctag={tag}"), exception=True))
    sections.append(Section("Ausnahmen (config/allowlist.txt)", entries=exceptions))
    for s in sections:
        if s.stats:
            s.stats["published"] = len(s.rules)
    return sections


def render_list(cfg: dict, sections: list[Section], generated: str) -> str:
    project = cfg["project"]
    total = sum(len(s.rules) for s in sections)
    out = [f"! Title: {project['title']}",
           f"! Description: {project['description']}",
           f"! Homepage: {project['homepage']}",
           f"! License: {project['license']}",
           "! Expires: 1 day",
           f"! Client-Tag: {cfg['settings']['client_tag']}",
           f"! Rules: {total}",
           f"! Last modified: {generated}"]
    for s in sections:
        if s.entries or s.meta:
            out += ["!", f"! ===== {s.title} =====", *(f"! {m}" for m in s.meta), *map(str, s.entries)]
    return "\n".join(out) + "\n"


def report(sections: list[Section]) -> str:
    """Markdown-Zusammenfassung für Log und GitHub-Step-Summary."""
    rows = ["| Abschnitt | Regeln | Duplikate | redundant | per Allowlist entfernt | verworfen |",
            "|---|---:|---:|---:|---:|---:|"]
    details = []
    for s in sections:
        rows.append(f"| {s.title} | {len(s.rules)} | {s.duplicates} | {s.redundant} | {s.allowlisted} "
                    f"| {sum(s.rejected.values())} |")
        details += [f"- {s.title}: {n}× {reason} (z. B. {s.examples[reason]})" for reason, n in s.rejected.most_common()]
    total = sum(len(s.rules) for s in sections)
    return "\n".join([f"### Filterliste erzeugt: {total} Regeln", "", *rows, "",
                      *(["**Verworfene Zeilen**", "", *details] if details else [])]) + "\n"


def render_page(template: str, cfg: dict, status: dict, list_text: str, now: datetime) -> str:
    """Füllt die Projektseite mit den Werten des aktuellen Builds."""
    def line(text: str) -> str:
        if text[0] in "!#":
            return f'<span class="muted">{escape(text)}</span>'
        rule, _, tag = text.partition("ctag=")
        return escape(rule) + (f'<span class="tag">ctag={escape(tag)}</span>' if tag else "")

    lines = list_text.split("\n")
    head = [x for x in lines[:8] if x.startswith(("! Title:", "! Client-Tag:", "! Rules:", "! Last modified:"))]
    rules = [x for x in lines if x and x[0] not in "!#"][:6]
    local = now.astimezone(ZoneInfo("Europe/Berlin"))
    sources = status["sources"]
    return Template(template).substitute(
        {k: escape(str(v)) for k, v in status.items() if k != "sources"},
        homepage=escape(cfg["project"]["homepage"]), site_url=escape(cfg["project"]["site_url"]),
        list_url_wbr="/<wbr>".join(map(escape, cfg["project"]["list_url"].rsplit("/", 1))),
        generated_date=f"{local:%d.%m.%Y}", generated_time=f"{local:%H:%M}", source_count=len(sources),
        preview="\n".join(map(line, [*head, "!", *rules])) + '\n<span class="muted">…</span>',
        source_rows="\n".join(f'          <a href="{escape(s["homepage"])}"><b>{escape(s["name"])}</b>'
                              f'<span>{escape(s["license"])}</span><em>{s["published"]} Regeln</em></a>' for s in sources))


def write_atomic(path: Path, content: str) -> None:
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(content, "utf-8")
    os.replace(tmp, path)


def main(argv: list[str] | None = None, fetcher=fetch) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--config", type=Path, default=ROOT / "config" / "sources.toml")
    ap.add_argument("--out", type=Path, default=ROOT / "public", help="Ausgabeverzeichnis (GitHub Pages)")
    ap.add_argument("--previous", type=Path, default=ROOT / "filters" / LIST_NAME,
                    help="zuletzt veröffentlichte Liste für die Schrumpfungsprüfung")
    ap.add_argument("--site", type=Path, default=ROOT / "site", help="Vorlage der Projektseite")
    ap.add_argument("--allow-shrink", action="store_true", help="deutlich kleinere Liste trotzdem erzeugen")
    args = ap.parse_args(argv)
    try:
        cfg = load_config(args.config)
        sections = build(cfg, args.config.parent, fetcher)
        total = sum(len(s.rules) for s in sections)
        if args.previous.is_file() and not args.allow_shrink:
            old, limit = count_rules(args.previous.read_text("utf-8")), cfg["settings"]["max_shrink_percent"]
            if total < old * (1 - limit / 100):
                raise BuildError(f"neue Liste hätte nur {total} statt bisher {old} Regeln (mehr als {limit} % weniger). "
                                 "Bei Absicht den Workflow manuell mit 'allow_shrink' starten.")
    except BuildError as e:
        notice("error", f"Filterliste NICHT aktualisiert – die bisherige Version bleibt online. Ursache: {e}")
        return 1

    now = datetime.now(timezone.utc).replace(microsecond=0)
    generated = now.isoformat().replace("+00:00", "Z")
    summary = report(sections)
    print(summary)
    for s in sections:
        for reason, n in s.rejected.items():
            notice("warning", f"{s.title}: {n} Zeile(n) verworfen – {reason} ({s.examples[reason]})")
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(path, "a", encoding="utf-8") as fh:
            fh.write(summary)

    sources = [s.stats for s in sections if s.stats]
    exceptions = len(sections[-1].rules)
    status = {"title": cfg["project"]["title"], "generated": generated, "rules": total,
              "block_rules": total - exceptions, "exceptions": exceptions,
              "client_tag": cfg["settings"]["client_tag"], "list_url": cfg["project"]["list_url"], "sources": sources}
    list_text = render_list(cfg, sections, generated)
    page = render_page((args.site / "index.html").read_text("utf-8"), cfg, status, list_text, now)
    shutil.copytree(args.site, args.out, dirs_exist_ok=True, ignore=shutil.ignore_patterns("index.html"))
    write_atomic(args.out / LIST_NAME, list_text)
    write_atomic(args.out / "status.json", json.dumps(status, ensure_ascii=False, indent=2) + "\n")
    write_atomic(args.out / "index.html", page)
    print(f"Geschrieben: {args.out / LIST_NAME} ({total} Regeln)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
