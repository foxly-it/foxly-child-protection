"""Tests für Foxly Child Protection: python3 -m unittest discover -s tests -v"""

import io
import re
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))

import update_filters as uf  # noqa: E402
from validate_filters import validate  # noqa: E402

TAG = "user_child"


def rules(line, subdomains=True):
    return [str(r) for r in uf.parse_line(line, TAG, subdomains)]


class Workspace:
    """Temporäres Repository mit Konfiguration und gefälschten Quellen."""

    def __init__(self, sources, allow="", block="", min_rules=1):
        self.dir = tempfile.TemporaryDirectory()
        self.root = Path(self.dir.name)
        (self.root / "config").mkdir()
        self.data = sources
        (self.root / "config" / "allowlist.txt").write_text(allow)
        (self.root / "config" / "blocklist.txt").write_text(block)
        toml = (ROOT / "config" / "sources.toml").read_text().split("\n[[sources]]")[0] + "\n"
        toml += "".join(f'[[sources]]\nname = "{n}"\nurl = "https://test.invalid/{n}"\nmin_rules = {min_rules}\n'
                        for n in sources)
        (self.root / "config" / "sources.toml").write_text(toml)
        self.cfg = uf.load_config(self.root / "config" / "sources.toml")

    def fetch(self, url, *_):
        value = self.data[url.rsplit("/", 1)[1]]
        if isinstance(value, Exception):
            raise value
        return value if isinstance(value, bytes) else value.encode()

    def build(self):
        return uf.build(self.cfg, self.root / "config", self.fetch)

    def output(self):
        sections = self.build()
        return [str(r) for s in sections for r in s.rules], sections

    def main(self, *extra):
        return uf.main(["--config", str(self.root / "config" / "sources.toml"), "--out", str(self.root / "public"),
                        "--previous", str(self.root / "filters" / uf.LIST_NAME), *extra], fetcher=self.fetch)


class ParseLine(unittest.TestCase):
    def test_01_plain_domain(self):
        self.assertEqual(rules("example.com"), ["||example.com^$ctag=user_child"])
        self.assertEqual(rules("Example.COM"), ["||example.com^$ctag=user_child"])
        self.assertEqual(rules("example.com", subdomains=False), ["|example.com^$ctag=user_child"])

    def test_02_adguard_rule_keeps_options(self):
        self.assertEqual(rules("||example.com^"), ["||example.com^$ctag=user_child"])
        self.assertEqual(rules("||example.com^$important"), ["||example.com^$important,ctag=user_child"])
        self.assertEqual(rules("||example.com^$dnstype=AAAA|A,important"),
                         ["||example.com^$dnstype=AAAA|A,important,ctag=user_child"])
        self.assertEqual(rules("||example.com^$denyallow=a.example.com|b.example.com"),
                         ["||example.com^$denyallow=a.example.com|b.example.com,ctag=user_child"])
        self.assertEqual(rules("|example.com^$important"), ["|example.com^$important,ctag=user_child"])

    def test_03_existing_client_tag(self):
        self.assertEqual(rules("||example.com^$ctag=user_child"), ["||example.com^$ctag=user_child"])
        self.assertEqual(rules("||example.com^$ctag=user_child,important"), ["||example.com^$ctag=user_child,important"])
        for line in ("||example.com^$ctag=device_pc", "||example.com^$ctag=~user_child",
                     "||example.com^$ctag=user_child|device_pc", "||example.com^$ctag=user_child,ctag=user_child"):
            with self.assertRaises(uf.Rejected, msg=line):
                rules(line)

    def test_05_invalid_domains(self):
        for line in ("-bad.example", "bad-.example", "com", "a..example", "1.2.3.4", "münchen.de", "exa mple.com",
                     "example.c", "example.123", ("a" * 64) + ".example", ".".join(["abcdefghi"] * 26) + ".com",
                     "||bad_tld.exam_ple^", "example.com."):
            with self.assertRaises(uf.Rejected, msg=line):
                rules(line)
        self.assertEqual(rules("xn--mnchen-3ya.de"), ["||xn--mnchen-3ya.de^$ctag=user_child"])
        self.assertEqual(rules("ads_1.example.com"), ["||ads_1.example.com^$ctag=user_child"])

    def test_11_hosts_file_lines(self):
        self.assertEqual(rules("0.0.0.0 a.example b.example"),
                         ["||a.example^$ctag=user_child", "||b.example^$ctag=user_child"])
        self.assertEqual(rules("127.0.0.1\tads.example  # Tracker"), ["||ads.example^$ctag=user_child"])
        self.assertEqual(rules("::1 ip6-localhost"), [])
        self.assertEqual(rules("127.0.0.1 localhost"), [])
        self.assertEqual(rules("0.0.0.0 0.0.0.0"), [])
        self.assertEqual(rules(":: tracker.example", subdomains=False), ["|tracker.example^$ctag=user_child"])
        for line in ("1.2.3.4 evil.example", "192.0.2.10 bank.example", "0.0.0.0 bad..example"):
            with self.assertRaises(uf.Rejected, msg=line):
                rules(line)

    def test_13_unexpected_options(self):
        for line in ("||example.com^$dnsrewrite=1.2.3.4", "||example.com^$client=192.0.2.1", "||example.com^$badfilter",
                     "||example.com^$foo", "||example.com^$important,important", "||example.com^$",
                     "||example.com^$important,", "||example.com^$Important", "||example.com^$important=1",
                     "||example.com^$denyallow=", "||example.com^$dnstype=A;B", "||example.com^$third-party"):
            with self.assertRaises(uf.Rejected, msg=line):
                rules(line)

    def test_15_unsupported_rules_are_not_converted(self):
        for line in ("/ads[0-9]+\\.example/", "*ads*", "||example.com", "example.com$ctag=user_child", "@@||example.com^",
                     "example.com##.banner", "||example.com^|", "||*.example.com^", "|https://example.com^",
                     "example.com^", "example.com other.example", "@@example.com", "||ex*ample.com^"):
            with self.assertRaises(uf.Rejected, msg=line):
                rules(line)


class Build(unittest.TestCase):
    def test_04_duplicates_across_formats_and_sources(self):
        ws = Workspace({"a": "example.com\n||example.com^\n0.0.0.0 example.com\n||x.example^$important,dnstype=A\n",
                        "b": "||EXAMPLE.com^$ctag=user_child\n||x.example^$dnstype=A,important\n"})
        out, sections = ws.output()
        self.assertEqual(out, ["||example.com^$ctag=user_child", "||x.example^$important,dnstype=A,ctag=user_child"])
        self.assertEqual([s.duplicates for s in sections[:2]], [2, 2])

    def test_redundant_subdomains_are_compressed(self):
        ws = Workspace({"a": "www.example.com\nexample.com\n||cdn.example.com^$important\n|example.com^\n"})
        out, sections = ws.output()
        self.assertEqual(out, ["||example.com^$ctag=user_child", "||cdn.example.com^$important,ctag=user_child"])
        self.assertEqual(sections[0].redundant, 2)

    def test_06_empty_source_fails(self):
        for content in ("", "# nur Kommentare\n! kein Inhalt\n", "\n\n"):
            with self.assertRaisesRegex(uf.BuildError, "nur 0 gültige Regeln"):
                Workspace({"a": content}).build()
        with self.assertRaisesRegex(uf.BuildError, "Minimum 3"):
            Workspace({"a": "a.example\nb.example\n"}, min_rules=3).build()

    def test_07_unreachable_source_fails_and_keeps_previous_list(self):
        with self.assertRaisesRegex(uf.BuildError, "Download fehlgeschlagen"):
            uf.fetch("https://127.0.0.1:9/liste.txt", 1000, 2, retries=1)
        with self.assertRaisesRegex(uf.BuildError, "nur HTTPS"):
            uf.fetch("http://example.com/liste.txt", 1000, 2)
        ws = Workspace({"a": "ok.example\n", "b": uf.BuildError("Download fehlgeschlagen: HTTP 404 Not Found")})
        public = ws.root / "public"
        public.mkdir()
        (public / uf.LIST_NAME).write_text("ALTE LISTE\n")
        self.assertEqual(ws.main(), 1)
        self.assertEqual((public / uf.LIST_NAME).read_text(), "ALTE LISTE\n")

    def test_download_size_limit(self):
        self.assertEqual(uf.read_limited(io.BytesIO(b"x" * 10), 10), b"x" * 10)
        with self.assertRaisesRegex(uf.BuildError, "größer als 10 Bytes"):
            uf.read_limited(io.BytesIO(b"x" * 11), 10)

    def test_08_allowlist_removes_rules_and_subdomains(self):
        ws = Workspace({"a": "schule.example\nwww.schule.example\n||cdn.schule.example^$important\nandere.example\n"},
                       allow="schule.example  # Schulportal\n")
        out, sections = ws.output()
        self.assertEqual(out, ["||andere.example^$ctag=user_child"])
        self.assertEqual(sections[0].allowlisted, 3)

    def test_08_allowlist_creates_exception_only_when_needed(self):
        ws = Workspace({"a": "example.org\n||imp.example^$important\nfrei.example\n"},
                       allow="lernen.example.org\nsub.imp.example\n@@frei.example\n@@extern.example\n")
        out, _ = ws.output()
        self.assertEqual(out, ["||example.org^$ctag=user_child", "||imp.example^$important,ctag=user_child",
                               "@@||lernen.example.org^$ctag=user_child",
                               "@@||sub.imp.example^$important,ctag=user_child",
                               "@@||frei.example^$ctag=user_child", "@@||extern.example^$ctag=user_child"])

    def test_09_blocklist_entries(self):
        ws = Workspace({"a": "quelle.example\n"}, block="eigen.example\n# Kommentar\nEIGEN.example\nquelle.example\n")
        out, sections = ws.output()
        self.assertEqual(out, ["||quelle.example^$ctag=user_child", "||eigen.example^$ctag=user_child"])
        self.assertEqual(sections[1].duplicates, 1)

    def test_user_files_reject_invalid_domains(self):
        for content in ("||example.com^\n", "*.example.com\n", "example\n", "münchen.de\n"):
            with self.assertRaisesRegex(uf.BuildError, "blocklist.txt, Zeile 1"):
                Workspace({"a": "a.example\n"}, block=content).build()
        with self.assertRaisesRegex(uf.BuildError, "keine gültige Domain"):
            Workspace({"a": "a.example\n"}, block="@@marker.example\n").build()

    def test_10_comments_preserved_in_order(self):
        ws = Workspace({"a": "[Adblock Plus 2.0]\n! Title: Quelle\n# Kategorie VPN\nvpn.example # Kommentar\n"
                             "! Kategorie Glücksspiel\ncasino.example\n"})
        entries = ws.build()[0].entries
        self.assertEqual([str(e) for e in entries], ["! Title: Quelle", "# Kategorie VPN",
                                                     "||vpn.example^$ctag=user_child", "! Kategorie Glücksspiel",
                                                     "||casino.example^$ctag=user_child"])

    def test_12_broken_encoding_and_html(self):
        for data, msg in ((b"ok.example\n\xff\xfe\n", "kein gültiges UTF-8"),
                          ("café.example\n".encode("latin-1"), "kein gültiges UTF-8"),
                          (b"<!DOCTYPE html><html>Fehler</html>", "HTML-Seite"),
                          (b"  <html><body>Captive Portal", "HTML-Seite")):
            with self.assertRaisesRegex(uf.BuildError, msg):
                Workspace({"a": data}).build()
        out, _ = Workspace({"a": b"\xef\xbb\xbfbom.example\r\n"}).output()
        self.assertEqual(out, ["||bom.example^$ctag=user_child"])
        section = Workspace({"a": "ok.example\nnul\x00.example\n# Kommentar\x1b[31m\nlang.example" + "x" * 1100})
        sec = section.build()[0]
        self.assertEqual([str(r) for r in sec.rules], ["||ok.example^$ctag=user_child"])
        self.assertEqual(sum(sec.rejected.values()), 3)

    def test_14_conflict_allowlist_wins_over_blocklist(self):
        ws = Workspace({"a": "x.example\n"}, block="beides.example\nsub.frei.example\nparent.example\n",
                       allow="beides.example\nfrei.example\nkind.parent.example\n")
        out, _ = ws.output()
        self.assertEqual(out, ["||x.example^$ctag=user_child", "||parent.example^$ctag=user_child",
                               "@@||kind.parent.example^$ctag=user_child"])

    def test_rejected_lines_are_reported_safely(self):
        sec = Workspace({"a": "ok.example\n0.0.0.0\tbad..example\n::warning::`inject`$x\n"}).build()[0]
        self.assertEqual(sum(sec.rejected.values()), 2)
        for example in sec.examples.values():
            self.assertNotIn("\t", example)
            self.assertNotIn("`", example)


class Output(unittest.TestCase):
    def test_main_writes_valid_list_and_validator_accepts_it(self):
        ws = Workspace({"a": "! Kopf\nfoo.example\n||bar.example^$important\n"}, allow="@@frei.example\n")
        self.assertEqual(ws.main(), 0)
        text = (ws.root / "public" / uf.LIST_NAME).read_text()
        self.assertTrue(text.startswith("! Title: Foxly Child Protection\n"))
        self.assertIn("! Rules: 3\n", text)
        self.assertEqual(validate(text, TAG), [])
        self.assertIn("3", (ws.root / "public" / "index.html").read_text())
        self.assertIn('"rules": 3', (ws.root / "public" / "status.json").read_text())

    def test_shrink_protection(self):
        ws = Workspace({"a": "a.example\n"})
        (ws.root / "filters").mkdir()
        (ws.root / "filters" / uf.LIST_NAME).write_text("".join(f"||d{i}.example^$ctag=user_child\n" for i in range(10)))
        self.assertEqual(ws.main(), 1)
        self.assertFalse((ws.root / "public" / uf.LIST_NAME).exists())
        self.assertEqual(ws.main("--allow-shrink"), 0)

    def test_validator_rejects_broken_lists(self):
        head = "! Title: X\n! Rules: 1\n"
        cases = {
            head + "||a.example^\n": "ctag=user_child fehlt",
            head + "a.example$ctag=user_child\n": "keine gültige",
            head + "||a.example^$ctag=device_pc\n": "abweichendes Client-Tag",
            head + "||a.example^$dnsrewrite=1.2.3.4,ctag=user_child\n": "nicht unterstützte",
            "! Title: X\n! Rules: 2\n||a.example^$ctag=user_child\n||a.example^$ctag=user_child\n": "doppelte Regel",
            head + "||a.example^$ctag=user_child\n||b.example^$ctag=user_child\n": "passt nicht",
            head + "||a.example^$ctag=user_child": "Zeilenumbruch",
            "||a.example^$ctag=user_child\n": "Title",
            head + "0.0.0.0 a.example\n": "keine gültige",
        }
        for text, expected in cases.items():
            self.assertTrue(any(expected in e for e in validate(text, TAG)), f"{expected!r} nicht gemeldet für {text!r}")
        self.assertTrue(validate(head + "||a.example^$ctag=user_child\n", TAG, min_rules=5))

    def test_repository_config_is_valid(self):
        cfg = uf.load_config(ROOT / "config" / "sources.toml")
        self.assertEqual(cfg["settings"]["client_tag"], TAG)
        self.assertTrue(all(s["url"].startswith("https://") for s in cfg["sources"]))
        uf.read_domain_file(ROOT / "config" / "allowlist.txt", allow_marker=True)
        uf.read_domain_file(ROOT / "config" / "blocklist.txt")


class Workflows(unittest.TestCase):
    """Schutz vor unbeabsichtigten Änderungen an den Workflow-Dateien."""

    def test_actions_pinned_and_permissions_minimal(self):
        files = sorted((ROOT / ".github" / "workflows").glob("*.yml"))
        self.assertTrue(files)
        for path in files:
            text = path.read_text()
            self.assertRegex(text, r"(?m)^permissions: \{\}$", f"{path.name}: globale Rechte nicht auf {{}} gesetzt")
            self.assertNotIn("pull_request_target", text, path.name)
            for ref in re.findall(r"uses:\s*(\S+)", text):
                if not ref.startswith("./"):
                    self.assertRegex(ref, r"^actions/[\w.-]+@[0-9a-f]{40}$", f"{path.name}: {ref} nicht per SHA gepinnt")


if __name__ == "__main__":
    unittest.main()
