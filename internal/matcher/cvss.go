package matcher

import (
	"fmt"
	"math"
	"strings"
)

// cvss3BaseScore computes the base score of a CVSS v3.0 or v3.1 vector such
// as "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", following section 7 of
// https://www.first.org/cvss/v3.1/specification-document.
func cvss3BaseScore(vector string) (float64, error) {
	parts := strings.Split(vector, "/")
	if len(parts) == 0 || !strings.HasPrefix(parts[0], "CVSS:3") {
		return 0, fmt.Errorf("not a CVSS v3 vector: %q", vector)
	}
	m := make(map[string]string, len(parts))
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return 0, fmt.Errorf("malformed metric %q", p)
		}
		m[k] = v
	}

	weights := map[string]map[string]float64{
		"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
		"AC": {"L": 0.77, "H": 0.44},
		"UI": {"N": 0.85, "R": 0.62},
		"C":  {"H": 0.56, "L": 0.22, "N": 0},
		"I":  {"H": 0.56, "L": 0.22, "N": 0},
		"A":  {"H": 0.56, "L": 0.22, "N": 0},
	}
	w := make(map[string]float64, len(weights))
	for metric, values := range weights {
		v, ok := values[m[metric]]
		if !ok {
			return 0, fmt.Errorf("missing or invalid %s in %q", metric, vector)
		}
		w[metric] = v
	}

	changed := m["S"] == "C"
	if !changed && m["S"] != "U" {
		return 0, fmt.Errorf("missing or invalid S in %q", vector)
	}
	// Privileges Required weighs more when scope changes.
	var pr float64
	switch m["PR"] {
	case "N":
		pr = 0.85
	case "L":
		pr = 0.62
		if changed {
			pr = 0.68
		}
	case "H":
		pr = 0.27
		if changed {
			pr = 0.5
		}
	default:
		return 0, fmt.Errorf("missing or invalid PR in %q", vector)
	}

	iss := 1 - (1-w["C"])*(1-w["I"])*(1-w["A"])
	var impact float64
	if changed {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	if impact <= 0 {
		return 0, nil
	}
	exploitability := 8.22 * w["AV"] * w["AC"] * pr * w["UI"]
	if changed {
		return roundUp(math.Min(1.08*(impact+exploitability), 10)), nil
	}
	return roundUp(math.Min(impact+exploitability, 10)), nil
}

// roundUp returns the smallest number with one decimal place that is >= x,
// using the integer arithmetic from CVSS v3.1 Appendix A to avoid
// floating-point artefacts.
func roundUp(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return float64(i/10000+1) / 10
}
