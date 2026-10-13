// Command engine-check prüft eine erzeugte Filterliste mit urlfilter, der
// Filter-Engine von AdGuard Home (gleiche Version wie im aktuellen Release):
//
//   - jede Regel wird von AdGuard Home fehlerfrei geparst,
//   - alle Regeln tragen dasselbe Client-Tag,
//   - Sperren greifen für Clients mit diesem Tag inklusive Subdomains,
//   - Clients ohne Tag oder mit anderem Tag werden nie blockiert,
//   - Ausnahmen geben die Domain für getaggte Clients frei.
//
// Aufruf: go run . <filterliste>
package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/AdguardTeam/golibs/container"
	"github.com/AdguardTeam/urlfilter"
	"github.com/AdguardTeam/urlfilter/filterlist"
	"github.com/AdguardTeam/urlfilter/rules"
)

var ruleRe = regexp.MustCompile(`^(@@)?(\|\|?)([^^]+)\^\$(.*)$`)

func main() {
	if len(os.Args) != 2 {
		fail("Aufruf: engine-check <filterliste>")
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		fail("Filterliste nicht lesbar: %v", err)
	}

	type entry struct {
		host         string
		exact, plain bool
	}
	var blocks, allows []entry
	tag := ""
	for i, line := range strings.Split(string(data), "\n") {
		if line == "" || line[0] == '!' || line[0] == '#' {
			continue
		}
		if _, err = rules.NewNetworkRule(line, 1); err != nil {
			fail("Zeile %d wird von AdGuard Home nicht akzeptiert: %q: %v", i+1, line, err)
		}
		m := ruleRe.FindStringSubmatch(line)
		if m == nil {
			fail("Zeile %d hat keine ||domain^$…-Form: %q", i+1, line)
		}
		var ruleTag string
		plain := true
		for _, mod := range strings.Split(m[4], ",") {
			name, value, _ := strings.Cut(mod, "=")
			switch name {
			case "ctag":
				ruleTag = value
			case "important", "dnstype", "denyallow":
				plain = false
			default:
				fail("Zeile %d: unzulässige Option %q: %q", i+1, name, line)
			}
		}
		if tag == "" {
			tag = ruleTag
		}
		if ruleTag == "" || ruleTag != tag {
			fail("Zeile %d: Client-Tag %q statt %q: %q", i+1, ruleTag, tag, line)
		}
		e := entry{host: m[3], exact: m[2] == "|", plain: plain}
		if m[1] != "" {
			allows = append(allows, e)
		} else {
			blocks = append(blocks, e)
		}
	}
	if len(blocks) == 0 {
		fail("keine Sperrregeln gefunden")
	}

	storage, err := filterlist.NewRuleStorage([]filterlist.Interface{filterlist.NewBytes(&filterlist.BytesConfig{
		ID: 1, RulesText: data, IgnoreCosmetic: true,
	})})
	if err != nil {
		fail("Regelspeicher: %v", err)
	}
	engine := urlfilter.NewDNSEngine(storage)
	blocked := func(host string, tags ...string) bool {
		res, ok := engine.MatchRequest(&urlfilter.DNSRequest{
			Hostname:   host,
			ClientTags: container.NewSortedSliceSet(tags...),
			DNSType:    1, // A
		})
		return ok && res.NetworkRule != nil && !res.NetworkRule.Whitelist
	}
	allowed := func(host string) bool {
		for _, a := range allows {
			if host == a.host || strings.HasSuffix(host, "."+a.host) {
				return true
			}
		}
		return false
	}

	for _, b := range blocks {
		probes := []string{b.host}
		if !b.exact {
			probes = append(probes, "probe-sub."+b.host)
		}
		for _, h := range probes {
			if blocked(h) || blocked(h, "user_regular") || blocked(h, "device_pc") {
				fail("%s wird auch für Clients ohne %s blockiert", h, tag)
			}
			if b.plain && !allowed(h) && !blocked(h, tag) {
				fail("%s wird für Clients mit %s NICHT blockiert", h, tag)
			}
		}
		if h := "foxly-probe-" + b.host; blocked(h, tag) {
			fail("Teilstring-Treffer: %s wird blockiert (Regel ohne ||/^-Anker?)", h)
		}
	}
	for _, a := range allows {
		if blocked(a.host, tag) {
			fail("Ausnahme für %s greift nicht", a.host)
		}
	}
	fmt.Printf("engine-check: %d Sperr- und %d Ausnahmeregeln mit AdGuard-Home-Engine geprüft (Tag %s)\n",
		len(blocks), len(allows), tag)
}

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "::error::engine-check: "+format+"\n", args...)
	os.Exit(1)
}
