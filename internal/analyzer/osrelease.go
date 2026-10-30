package analyzer

import (
	"bufio"
	"bytes"
	"fmt"
	"io/fs"
	"regexp"
	"strings"
)

// osRelease holds the fields of /etc/os-release that identify a distro.
// See https://www.freedesktop.org/software/systemd/man/os-release.html.
type osRelease struct {
	ID        string // "debian", "ubuntu", "alpine"
	VersionID string // "12", "22.04", "3.19.1"
	Version   string // "22.04.4 LTS (Jammy Jellyfish)"
}

var osReleasePaths = []string{"etc/os-release", "usr/lib/os-release"}

func readOSRelease(fsys fs.FS) (osRelease, error) {
	for _, p := range osReleasePaths {
		data, err := fs.ReadFile(fsys, p)
		if err != nil {
			continue
		}
		var r osRelease
		sc := bufio.NewScanner(bytes.NewReader(data))
		for sc.Scan() {
			key, value, ok := strings.Cut(sc.Text(), "=")
			if !ok {
				continue
			}
			value = strings.Trim(strings.TrimSpace(value), `"'`)
			switch strings.TrimSpace(key) {
			case "ID":
				r.ID = value
			case "VERSION_ID":
				r.VersionID = value
			case "VERSION":
				r.Version = value
			}
		}
		return r, nil
	}
	return osRelease{}, fmt.Errorf("no os-release file (looked for %s)", strings.Join(osReleasePaths, ", "))
}

var majorMinor = regexp.MustCompile(`^(\d+)\.(\d+)`)

// osvEcosystem returns the OSV ecosystem for the distro, such as
// "Debian:12", "Ubuntu:22.04:LTS", or "Alpine:v3.19".
func (r osRelease) osvEcosystem() (string, error) {
	switch r.ID {
	case "debian":
		if r.VersionID == "" {
			return "", fmt.Errorf("debian without VERSION_ID (testing or unstable) is not supported")
		}
		return "Debian:" + r.VersionID, nil
	case "ubuntu":
		if r.VersionID == "" {
			return "", fmt.Errorf("ubuntu without VERSION_ID")
		}
		if strings.Contains(r.Version, "LTS") {
			return "Ubuntu:" + r.VersionID + ":LTS", nil
		}
		return "Ubuntu:" + r.VersionID, nil
	case "alpine":
		m := majorMinor.FindStringSubmatch(r.VersionID)
		if m == nil {
			return "", fmt.Errorf("alpine VERSION_ID %q has no major.minor", r.VersionID)
		}
		return "Alpine:v" + m[1] + "." + m[2], nil
	}
	return "", fmt.Errorf("unsupported distro %q", r.ID)
}
