package relay

import (
	"os"
	"strings"
)

// parseARPTable parses the contents of /proc/net/arp and returns the MAC for the given IP.
// The format is fixed-column whitespace-delimited:
// Field[0]=IP, Field[1]=HWtype, Field[2]=Flags, Field[3]=HWaddress, Field[4]=Mask, Field[5]=Device
// Returns empty string if not found.
func parseARPTable(arpContent, ip string) string {
	for i, line := range strings.Split(arpContent, "\n") {
		if i == 0 {
			continue // skip header
		}
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == ip {
			return fields[3]
		}
	}
	return ""
}

// readFile reads a file from disk and returns its contents.
func readFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}
