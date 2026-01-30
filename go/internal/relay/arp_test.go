package relay

import "testing"

func TestParseARPTable(t *testing.T) {
	validARP := `IP address       HW type     Flags       HW address            Mask     Device
192.168.0.1      0x1         0x2         30:65:EC:6F:C4:58     *        eth0
192.168.0.2      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0
10.0.0.1         0x1         0x2         11:22:33:44:55:66     *        wlan0`

	tests := []struct {
		name     string
		content  string
		ip       string
		expected string
	}{
		{"found first entry", validARP, "192.168.0.1", "30:65:EC:6F:C4:58"},
		{"found second entry", validARP, "192.168.0.2", "aa:bb:cc:dd:ee:ff"},
		{"found third entry", validARP, "10.0.0.1", "11:22:33:44:55:66"},
		{"IP not in table", validARP, "172.16.5.1", ""},
		{"empty content", "", "192.168.0.1", ""},
		{"header only", "IP address       HW type     Flags       HW address            Mask     Device\n", "192.168.0.1", ""},
		{"malformed lines", "not a valid arp table\ngarbage data", "192.168.0.1", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseARPTable(tt.content, tt.ip)
			if got != tt.expected {
				t.Errorf("parseARPTable(%q) = %q, want %q", tt.ip, got, tt.expected)
			}
		})
	}
}

func TestParseARPTableDuplicateIP(t *testing.T) {
	// When multiple entries exist for the same IP, the first match wins
	arp := `IP address       HW type     Flags       HW address            Mask     Device
192.168.0.1      0x1         0x2         aa:aa:aa:aa:aa:aa     *        eth0
192.168.0.1      0x1         0x2         bb:bb:bb:bb:bb:bb     *        eth1`

	got := parseARPTable(arp, "192.168.0.1")
	if got != "aa:aa:aa:aa:aa:aa" {
		t.Errorf("parseARPTable with duplicate IP = %q, want first match %q", got, "aa:aa:aa:aa:aa:aa")
	}
}
