#!/usr/bin/env python3
"""Prüft eine erzeugte Filterliste, bevor sie veröffentlicht wird.

Jede Regelzeile muss exakt die Form (@@)||domain^$…,ctag=<tag> bzw. |domain^
haben, nur erlaubte Optionen tragen, genau einmal vorkommen und die Anzahl im
Kopf (! Rules:) muss stimmen. Bei einem Fehler endet das Skript mit Code 1.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from update_filters import ADBLOCK_RE, MAX_LINE, ROOT, Rejected, is_domain, load_config, notice, tag_modifiers


def validate(text: str, tag: str, min_rules: int = 1) -> list[str]:
    errors = []
    lines = text.split("\n")
    if not lines[0].startswith("! Title:"):
        errors.append("Zeile 1: Kopfzeile '! Title:' fehlt")
    if lines[-1] != "":
        errors.append("Datei endet nicht mit einem Zeilenumbruch (unvollständig geschrieben?)")
    seen, rules, declared = set(), 0, None
    for no, line in enumerate(lines, 1):
        if not line:
            continue
        if line != line.strip() or len(line) > MAX_LINE or not line.replace("\t", " ").isprintable():
            errors.append(f"Zeile {no}: Leerraum am Rand, Steuerzeichen oder zu lang")
            continue
        if line[0] in "!#":
            if line.startswith("! Rules:") and declared is None:
                declared = line[8:].strip()
            continue
        rules += 1
        m = ADBLOCK_RE.fullmatch(line)
        try:
            if not m or not is_domain(m[3]):
                raise Rejected("keine gültige ||domain^-Regel")
            if not line.isascii() or m[4] is None or tag_modifiers(m[4], tag) != tuple(m[4].split(",")):
                raise Rejected(f"$ctag={tag} fehlt")
        except Rejected as e:
            errors.append(f"Zeile {no}: {e}: {line}")
            continue
        key = (m[1], m[2], m[3], frozenset(m[4].split(",")))
        if key in seen:
            errors.append(f"Zeile {no}: doppelte Regel {line}")
        seen.add(key)
    if declared != str(rules):
        errors.append(f"Kopfzeile '! Rules: {declared}' passt nicht zu {rules} tatsächlichen Regeln")
    if rules < min_rules:
        errors.append(f"nur {rules} Regeln, erwartet mindestens {min_rules}")
    return errors


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("list", type=Path)
    ap.add_argument("--config", type=Path, default=ROOT / "config" / "sources.toml")
    args = ap.parse_args(argv)
    cfg = load_config(args.config)
    min_rules = sum(s.get("min_rules", 1) for s in cfg["sources"] if s.get("enabled", True))
    try:
        text = args.list.read_text("utf-8")
    except (OSError, UnicodeDecodeError) as e:
        notice("error", f"Filterliste nicht lesbar: {e}")
        return 1
    errors = validate(text, cfg["settings"]["client_tag"], min_rules)
    for err in errors[:50]:
        notice("error", f"Validierung: {err}")
    if errors:
        notice("error", f"{len(errors)} Fehler – Filterliste wird NICHT veröffentlicht")
        return 1
    print(f"Validierung erfolgreich: {args.list}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
