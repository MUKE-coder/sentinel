package core

// CVSS holds a Common Vulnerability Scoring System score and the canonical
// vector string that produced it. Used for alert prioritization and
// downstream SOC tooling that expects CVSS-style severity.
type CVSS struct {
	Score  float64
	Vector string
}

// defaultCVSS maps each ThreatType to a reasonable default CVSS:3.1 vector.
// Tuned conservatively — these are "we observed an attempt" scores, not
// "the attempt succeeded" scores. Detectors that have more information
// (e.g. confirmed RCE) should override these on the produced ThreatEvent.
var defaultCVSS = map[ThreatType]CVSS{
	ThreatSQLi: {
		Score:  7.5,
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
	},
	ThreatXSS: {
		Score:  6.1,
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
	},
	ThreatCommandInjection: {
		Score:  9.8,
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
	},
	ThreatSSRF: {
		Score:  9.1,
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
	},
	ThreatPathTraversal: {
		Score:  7.5,
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
	},
	ThreatXXE: {
		Score:  8.2,
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L",
	},
	ThreatLFI: {
		Score:  7.5,
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
	},
	ThreatOpenRedirect: {
		Score:  6.1,
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
	},
	ThreatPrototypePollution: {
		Score:  7.3,
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L",
	},
	ThreatBruteForce: {
		Score:  5.3,
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
	},
	ThreatRateLimitExceeded: {
		Score:  3.7,
		Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
	},
	ThreatAnomalyDetected: {
		Score:  5.3,
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
	},
	ThreatScanning: {
		Score:  3.1,
		Vector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
	},
	ThreatCSPViolation: {
		// Low by default — most CSP reports are extensions or harmless
		// inline scripts. Aggregate volume is the real signal; escalate
		// downstream if needed.
		Score:  3.1,
		Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",
	},
}

// DefaultCVSSForType returns the default CVSS score + vector for a given
// threat type, or (0, "") if no default is registered. Detection code uses
// this to populate ThreatEvent.CVSS / .CVSSVector when a more specific
// score is unavailable.
func DefaultCVSSForType(t string) CVSS {
	return defaultCVSS[ThreatType(t)]
}

// DefaultCVSSForTypes returns the highest CVSS score from a slice of
// threat-type strings. When multiple match (e.g. SQLi + CommandInjection),
// the worst wins — that's the score that should drive alert routing.
func DefaultCVSSForTypes(types []string) CVSS {
	var best CVSS
	for _, t := range types {
		c := DefaultCVSSForType(t)
		if c.Score > best.Score {
			best = c
		}
	}
	return best
}
