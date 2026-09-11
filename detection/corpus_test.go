package detection

import (
	"bufio"
	"os"
	"strings"
	"testing"

	sentinel "github.com/MUKE-coder/sentinel/v2/core"
)

// corpusSample is one line of testdata/benign.tsv or testdata/attacks.tsv.
type corpusSample struct {
	category string // attacks only
	location string
	input    string
}

func loadCorpus(t *testing.T, path string, withCategory bool) []corpusSample {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	var out []corpusSample
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, "\t", 3)
		var s corpusSample
		switch {
		case withCategory && len(fields) == 3:
			s = corpusSample{category: fields[0], location: fields[1], input: fields[2]}
		case !withCategory && len(fields) >= 2:
			s = corpusSample{location: fields[0], input: strings.Join(fields[1:], "\t")}
		default:
			t.Fatalf("%s: malformed line %q", path, line)
		}
		out = append(out, s)
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return out
}

func (s corpusSample) request() sentinel.InspectedRequest {
	req := sentinel.InspectedRequest{Method: "GET", Path: "/"}
	switch s.location {
	case "query":
		req.RawQuery = s.input
	case "body":
		req.Method = "POST"
		req.Body = s.input
	case "path":
		req.Path = s.input
	case "header":
		req.Headers = map[string][]string{"User-Agent": {s.input}}
	}
	return req
}

func uniformRules(level sentinel.RuleSensitivity) sentinel.RuleSet {
	return sentinel.RuleSet{
		SQLInjection: level, XSS: level, PathTraversal: level, CommandInjection: level,
		SSRF: level, XXE: level, LFI: level, OpenRedirect: level,
	}
}

func flagged(s corpusSample, rules sentinel.RuleSet) []ThreatMatch {
	return ApplySensitivity(ClassifyRequest(s.request()), rules)
}

// corpusLevels are the rule sets measured, in order of strictness, plus the
// defaults (strict, with medium for SSRF and open redirect).
func corpusLevels() []struct {
	name  string
	rules sentinel.RuleSet
} {
	var defaults sentinel.Config
	defaults.ApplyDefaults()
	return []struct {
		name  string
		rules sentinel.RuleSet
	}{
		{"low", uniformRules(sentinel.RuleLow)},
		{"medium", uniformRules(sentinel.RuleMedium)},
		{"strict", uniformRules(sentinel.RuleStrict)},
		{"defaults", defaults.WAF.Rules},
	}
}

// TestCorpus measures the built-in patterns against a corpus of
// legitimate-but-unusual traffic and a corpus of attacks, at every
// sensitivity level, and pins the results: a pattern change that raises
// the false-positive rate or lowers the detection rate fails here. Run with
// -v to print the table the docs publish.
func TestCorpus(t *testing.T) {
	benign := loadCorpus(t, "testdata/benign.tsv", false)
	attacks := loadCorpus(t, "testdata/attacks.tsv", true)

	// Ceilings (false positives) and floors (detections) pinned from the
	// measured results; tighten them when patterns improve. The false
	// positives left at "defaults" are inputs no pattern can tell from an
	// attack: SQL quoted in prose, a whole-value hex id, "../" in a search,
	// an encoded <script> tag, and absolute URLs in callback parameters
	// (Sentinel doesn't know your own host).
	type bound struct{ maxFP, minDetected int }
	bounds := map[string]bound{
		"low":      {maxFP: 7, minDetected: 41},
		"medium":   {maxFP: 9, minDetected: 54},
		"strict":   {maxFP: 9, minDetected: 56},
		"defaults": {maxFP: 9, minDetected: 56},
	}

	t.Logf("corpus: %d benign samples, %d attacks", len(benign), len(attacks))
	t.Logf("%-9s %16s %18s", "level", "false positives", "attacks detected")
	for _, lvl := range corpusLevels() {
		fp, detected := 0, 0
		for _, s := range benign {
			if m := flagged(s, lvl.rules); len(m) > 0 {
				fp++
				if testing.Verbose() && lvl.name == "defaults" {
					t.Logf("  false positive: %s %q -> %s", s.location, s.input, m[0].PatternName)
				}
			}
		}
		for _, s := range attacks {
			if len(flagged(s, lvl.rules)) > 0 {
				detected++
			} else if testing.Verbose() && lvl.name == "defaults" {
				t.Logf("  missed: %s %s %q", s.category, s.location, s.input)
			}
		}
		t.Logf("%-9s %8d/%d (%4.1f%%) %9d/%d (%4.1f%%)", lvl.name,
			fp, len(benign), 100*float64(fp)/float64(len(benign)),
			detected, len(attacks), 100*float64(detected)/float64(len(attacks)))

		b := bounds[lvl.name]
		if fp > b.maxFP {
			t.Errorf("%s: %d false positives, ceiling is %d", lvl.name, fp, b.maxFP)
		}
		if detected < b.minDetected {
			t.Errorf("%s: %d attacks detected, floor is %d", lvl.name, detected, b.minDetected)
		}
	}
}
