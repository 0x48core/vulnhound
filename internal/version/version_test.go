package version

import "testing"

func TestCompare(t *testing.T) {
	tests := []struct {
		eco, a, b string
		want      int
	}{
		// Semver: Go and npm.
		{"Go", "v1.9.0", "v1.10.0", -1},
		{"Go", "1.9.1", "v1.9.1", 0},
		{"npm", "4.17.15", "4.17.21", -1},
		{"npm", "1.0.0-rc.1", "1.0.0", -1},

		// Debian / Ubuntu: dpkg ordering.
		{"Debian:12", "3.0.11-1~deb12u2", "3.0.11-1", -1}, // ~ sorts before end
		{"Debian:12", "3.0.11-1~deb12u2", "3.0.11-1~deb12u1", 1},
		{"Debian:12", "1:1.0", "2.0", 1}, // epoch wins
		{"Debian:12", "2.36-9+deb12u4", "2.36-9+deb12u10", -1},
		{"Debian:12", "1.2.3", "1.2.3-0", 0}, // no revision equals "-0": leading zeros are skipped
		{"Ubuntu:22.04:LTS", "1.1.1f-1ubuntu2.20", "1.1.1f-1ubuntu2.3", 1},
		{"Debian:12", "7.88.1-10+deb12u5", "7.88.1-10+deb12u5", 0},
		{"Debian:12", "1.0a", "1.0", 1},
		{"Debian:12", "1.0~rc1", "1.0", -1},

		// Alpine: apk ordering.
		{"Alpine:v3.19", "3.1.4-r5", "3.1.4-r6", -1},
		{"Alpine:v3.19", "3.1.4-r5", "3.1.10-r0", -1},
		{"Alpine:v3.19", "1.36.1-r15", "1.36.1-r15", 0},
		{"Alpine:v3.19", "1.0_rc1-r0", "1.0-r0", -1},
		{"Alpine:v3.19", "1.0_p1-r0", "1.0-r0", 1},
		{"Alpine:v3.19", "1.0-r0", "1.0.1-r0", -1},
		{"Alpine:v3.19", "1.1a-r0", "1.1-r0", 1},
		{"Alpine:v3.19", "8.5.0-r0", "8.4.99_git20230101-r3", 1},
	}
	for _, tt := range tests {
		got, ok := Compare(tt.eco, tt.a, tt.b)
		if !ok || got != tt.want {
			t.Errorf("Compare(%q, %q, %q) = %d, %v; want %d", tt.eco, tt.a, tt.b, got, ok, tt.want)
		}
		if back, _ := Compare(tt.eco, tt.b, tt.a); back != -tt.want {
			t.Errorf("Compare(%q, %q, %q) = %d; not antisymmetric", tt.eco, tt.b, tt.a, back)
		}
	}
}

func TestNotComparable(t *testing.T) {
	for _, tt := range []struct{ eco, v string }{
		{"Go", "latest"},
		{"Debian:12", "abc"},
		{"Debian:12", "x:1.0"},
		{"Alpine:v3.19", "1.0-rX"},
		{"Alpine:v3.19", "1.0_weird1"},
		{"PyPI", "1.0"},
	} {
		if Comparable(tt.eco, tt.v) {
			t.Errorf("Comparable(%q, %q) = true", tt.eco, tt.v)
		}
	}
}
