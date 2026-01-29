package relay

import (
	"os"
	"regexp"
)

var arpRegex = regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s.*\s(([a-fA-F\d]{1,2}:){5}[a-fA-F\d]{1,2})`)

// parseARPTable parses the contents of /proc/net/arp and returns the MAC for the given IP.
// Returns empty string if not found.
func parseARPTable(arpContent, ip string) string {
	matches := arpRegex.FindAllStringSubmatch(arpContent, -1)
	for _, m := range matches {
		if m[1] == ip {
			return m[2]
		}
	}
	return ""
}

func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
