package relay

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIsDuplicate(t *testing.T) {
	pr := &PacketRelay{}

	// Empty ring - nothing is duplicate
	if pr.isDuplicate(0x1234) {
		t.Error("expected 0x1234 to not be duplicate in empty ring")
	}

	pr.addChecksum(0x1234)

	if !pr.isDuplicate(0x1234) {
		t.Error("expected 0x1234 to be duplicate after adding")
	}

	// Different value should not be duplicate
	if pr.isDuplicate(0x5678) {
		t.Error("expected 0x5678 to not be duplicate")
	}
}

func TestAddChecksumMultiple(t *testing.T) {
	pr := &PacketRelay{}

	pr.addChecksum(0x0001)
	pr.addChecksum(0x0002)
	pr.addChecksum(0x0003)

	if !pr.isDuplicate(0x0001) {
		t.Error("expected 0x0001 to be duplicate")
	}
	if !pr.isDuplicate(0x0002) {
		t.Error("expected 0x0002 to be duplicate")
	}
	if !pr.isDuplicate(0x0003) {
		t.Error("expected 0x0003 to be duplicate")
	}
	if pr.isDuplicate(0x0004) {
		t.Error("expected 0x0004 to not be duplicate")
	}
}

func TestDuplicateRingBufferWrap(t *testing.T) {
	pr := &PacketRelay{}

	// Fill the ring buffer completely with values 0..255
	for i := 0; i < maxRecentChecksums; i++ {
		pr.addChecksum(uint16(i))
	}

	// All values 0..255 should be present
	for i := 0; i < maxRecentChecksums; i++ {
		if !pr.isDuplicate(uint16(i)) {
			t.Errorf("expected %d to be duplicate before wrap", i)
		}
	}

	// Add one more value, overwriting index 0 (which held value 0)
	pr.addChecksum(0xFFFF)

	// 0xFFFF should be found
	if !pr.isDuplicate(0xFFFF) {
		t.Error("expected 0xFFFF to be duplicate after adding")
	}

	// Value 0 was at index 0, now overwritten by 0xFFFF
	if pr.isDuplicate(0) {
		t.Error("expected 0 to no longer be duplicate after ring wrap")
	}

	// Values 1..255 should still be present
	for i := 1; i < maxRecentChecksums; i++ {
		if !pr.isDuplicate(uint16(i)) {
			t.Errorf("expected %d to still be duplicate after wrap", i)
		}
	}
}

func TestDuplicateRingBufferOverflow(t *testing.T) {
	pr := &PacketRelay{}

	// Add 2x the ring size to fully cycle through
	for i := 0; i < maxRecentChecksums*2; i++ {
		pr.addChecksum(uint16(i))
	}

	// Only the last maxRecentChecksums values should be present (256..511)
	for i := 0; i < maxRecentChecksums; i++ {
		if pr.isDuplicate(uint16(i)) {
			t.Errorf("expected %d to be evicted after full cycle", i)
		}
	}
	for i := maxRecentChecksums; i < maxRecentChecksums*2; i++ {
		if !pr.isDuplicate(uint16(i)) {
			t.Errorf("expected %d to be present", i)
		}
	}
}

func TestDuplicateDetectionSequentialStress(t *testing.T) {
	// The ring buffer is intentionally not safe for concurrent use.
	// It is only accessed from the single-threaded main loop.
	// This test validates correctness under heavy sequential use.
	pr := &PacketRelay{}

	for g := 0; g < 10; g++ {
		base := uint16(g) * 100
		for i := uint16(0); i < 100; i++ {
			pr.addChecksum(base + i)
			if !pr.isDuplicate(base + i) {
				t.Errorf("expected %d to be duplicate after adding", base+i)
			}
		}
	}
}

// --- Interface filter tests ---

func TestIsAllowedByFilterNoFilters(t *testing.T) {
	pr := &PacketRelay{}
	// With no filters, everything should be allowed
	if !pr.isAllowedByFilter("192.168.1.100", "eth0") {
		t.Error("expected allowed with no filters")
	}
	if !pr.isAllowedByFilter("10.0.0.1", "wlan0") {
		t.Error("expected allowed with no filters")
	}
}

func TestIsAllowedByFilter(t *testing.T) {
	pr := &PacketRelay{
		parsedFilters: []parsedFilter{
			{
				prefix: netip.MustParsePrefix("192.168.1.0/24"),
				ifaces: []string{"eth0", "eth1"},
			},
			{
				prefix: netip.MustParsePrefix("10.0.0.0/8"),
				ifaces: []string{"wlan0"},
			},
		},
	}

	tests := []struct {
		name    string
		srcAddr string
		txIface string
		allowed bool
	}{
		{"192.168.1.x to eth0 allowed", "192.168.1.100", "eth0", true},
		{"192.168.1.x to eth1 allowed", "192.168.1.50", "eth1", true},
		{"192.168.1.x to wlan0 blocked", "192.168.1.100", "wlan0", false},
		{"192.168.1.x to eth2 blocked", "192.168.1.1", "eth2", false},
		{"10.x to wlan0 allowed", "10.5.3.1", "wlan0", true},
		{"10.x to eth0 blocked", "10.5.3.1", "eth0", false},
		{"unmatched network defaults to allowed", "172.16.0.1", "eth0", true},
		{"unmatched network defaults to allowed any iface", "172.16.0.1", "wlan0", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pr.isAllowedByFilter(tt.srcAddr, tt.txIface)
			if got != tt.allowed {
				t.Errorf("isAllowedByFilter(%s, %s) = %v, want %v",
					tt.srcAddr, tt.txIface, got, tt.allowed)
			}
		})
	}
}

func TestParseIfFilterFile(t *testing.T) {
	t.Run("valid JSON with CIDR", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "filter.json")
		data := map[string][]string{
			"192.168.1.0/24": {"eth0", "eth1"},
			"10.0.0.0/8":    {"wlan0"},
		}
		raw, _ := json.Marshal(data)
		os.WriteFile(path, raw, 0644)

		filters, err := parseIfFilterFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(filters) != 2 {
			t.Fatalf("expected 2 filters, got %d", len(filters))
		}

		found24 := false
		found8 := false
		for _, f := range filters {
			if f.prefix == netip.MustParsePrefix("192.168.1.0/24") {
				found24 = true
				if len(f.ifaces) != 2 {
					t.Errorf("expected 2 interfaces for /24 filter, got %d", len(f.ifaces))
				}
			}
			if f.prefix == netip.MustParsePrefix("10.0.0.0/8") {
				found8 = true
				if len(f.ifaces) != 1 {
					t.Errorf("expected 1 interface for /8 filter, got %d", len(f.ifaces))
				}
			}
		}
		if !found24 {
			t.Error("missing filter for 192.168.1.0/24")
		}
		if !found8 {
			t.Error("missing filter for 10.0.0.0/8")
		}
	})

	t.Run("no CIDR suffix defaults to /32", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "filter.json")
		data := map[string][]string{
			"192.168.1.1": {"eth0"},
		}
		raw, _ := json.Marshal(data)
		os.WriteFile(path, raw, 0644)

		filters, err := parseIfFilterFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(filters) != 1 {
			t.Fatalf("expected 1 filter, got %d", len(filters))
		}
		expected := netip.MustParsePrefix("192.168.1.1/32")
		if filters[0].prefix != expected {
			t.Errorf("expected %s prefix, got %s", expected, filters[0].prefix)
		}
	})

	t.Run("nonexistent file", func(t *testing.T) {
		_, err := parseIfFilterFile("/nonexistent/path/filter.json")
		if err == nil {
			t.Error("expected error for nonexistent file")
		}
	})

	t.Run("invalid JSON", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "filter.json")
		os.WriteFile(path, []byte("not json"), 0644)

		_, err := parseIfFilterFile(path)
		if err == nil {
			t.Error("expected error for invalid JSON")
		}
	})

	t.Run("invalid CIDR bits", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "filter.json")
		os.WriteFile(path, []byte(`{"192.168.1.0/abc": ["eth0"]}`), 0644)

		_, err := parseIfFilterFile(path)
		if err == nil {
			t.Error("expected error for invalid CIDR bits")
		}
	})

	t.Run("empty filter map", func(t *testing.T) {
		dir := t.TempDir()
		path := filepath.Join(dir, "filter.json")
		os.WriteFile(path, []byte(`{}`), 0644)

		filters, err := parseIfFilterFile(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(filters) != 0 {
			t.Errorf("expected 0 filters, got %d", len(filters))
		}
	})
}

func TestParseIfFilterFileIntegration(t *testing.T) {
	// End-to-end: parse a filter file, then use isAllowedByFilter
	dir := t.TempDir()
	path := filepath.Join(dir, "filter.json")
	data := map[string][]string{
		"192.168.1.0/24": {"eth0", "eth1"},
	}
	raw, _ := json.Marshal(data)
	os.WriteFile(path, raw, 0644)

	filters, err := parseIfFilterFile(path)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	pr := &PacketRelay{parsedFilters: filters}

	if !pr.isAllowedByFilter("192.168.1.50", "eth0") {
		t.Error("expected 192.168.1.50 allowed to eth0")
	}
	if pr.isAllowedByFilter("192.168.1.50", "wlan0") {
		t.Error("expected 192.168.1.50 blocked to wlan0")
	}
	if !pr.isAllowedByFilter("10.0.0.1", "wlan0") {
		t.Error("expected 10.0.0.1 allowed to any interface (no matching filter)")
	}
}

// --- Buffer pool tests ---

func TestGetPutBuffer(t *testing.T) {
	bp := getBuffer(100)
	b := *bp
	if len(b) != 100 {
		t.Errorf("getBuffer(100) length = %d, want 100", len(b))
	}
	if cap(b) < 100 {
		t.Errorf("getBuffer(100) capacity = %d, want >= 100", cap(b))
	}
	// Write some data and return to pool
	for i := range b {
		b[i] = byte(i)
	}
	putBuffer(bp)

	// Get another buffer — should reuse from pool
	bp2 := getBuffer(50)
	b2 := *bp2
	if len(b2) != 50 {
		t.Errorf("getBuffer(50) length = %d, want 50", len(b2))
	}
	putBuffer(bp2)
}

func TestGetBufferLargerThanPool(t *testing.T) {
	// Request a buffer larger than the default pool capacity
	bp := getBuffer(maxPacketSize + 1000)
	b := *bp
	if len(b) != maxPacketSize+1000 {
		t.Errorf("getBuffer(%d) length = %d", maxPacketSize+1000, len(b))
	}
	putBuffer(bp)
}

// --- isENXIO tests ---

func TestIsENXIO(t *testing.T) {
	if !isENXIO(unix.ENXIO) {
		t.Error("expected isENXIO(unix.ENXIO) = true")
	}
	if isENXIO(unix.ENOENT) {
		t.Error("expected isENXIO(unix.ENOENT) = false")
	}
	if isENXIO(errors.New("some error")) {
		t.Error("expected isENXIO(generic error) = false")
	}
	if isENXIO(nil) {
		t.Error("expected isENXIO(nil) = false")
	}
}

// --- isDuplicate checksumCount clamp branch ---

func TestIsDuplicateChecksumCountClamp(t *testing.T) {
	// Directly set checksumCount beyond maxRecentChecksums to exercise
	// the clamping branch in isDuplicate.
	pr := &PacketRelay{}
	pr.checksumCount = maxRecentChecksums + 10
	pr.recentChecksums[0] = 0xABCD

	// Should still find the value (clamps search to maxRecentChecksums)
	if !pr.isDuplicate(0xABCD) {
		t.Error("expected isDuplicate to find 0xABCD with clamped count")
	}
	// Should not find a value that isn't there
	if pr.isDuplicate(0x1111) {
		t.Error("expected isDuplicate to not find 0x1111")
	}
}
