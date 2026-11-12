// Package gnss provides helpers to query the GNSS receiver exposed by a network
// device.
package gnss

import (
	"fmt"
	"strings"
)

// GNRMCSentenceCommand returns the shell command that reads a bounded window of
// the GNSS character device at devPath and extracts the first GNRMC sentence.
// Receivers can interleave UBX binary records with NMEA output, so the window is
// scanned instead of reading only the first line of the device.
func GNRMCSentenceCommand(devPath string) string {
	return fmt.Sprintf("export LC_ALL=C; timeout 3 cat %s 2>/dev/null | tr -d '\\r' | grep -a -o 'GNRMC,[^[:cntrl:]]*' | head -n 1", devPath)
}

// HasValidFix reports whether output contains a GNRMC sentence whose status
// field indicates a valid fix.
func HasValidFix(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		if strings.Contains(line, "GNRMC") {
			parts := strings.Split(line, ",")
			if len(parts) > 2 && parts[2] == "A" {
				return true
			}
		}
	}
	return false
}
