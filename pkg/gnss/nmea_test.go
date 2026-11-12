package gnss

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestHasValidFix(t *testing.T) {
	tests := []struct {
		name   string
		output string
		want   bool
	}{
		{
			name:   "valid fix",
			output: "$GNRMC,194844.00,A,3553.86724,N,07852.73886,W,0.000,,111126,,,A,V*0B\r\n",
			want:   true,
		},
		{
			name:   "binary prefix before sentence on same line",
			output: "\xb5\x62\x01\x07junk$GNRMC,194844.00,A,3553.86724,N,07852.73886,W,0.000,,111126,,,A,V*0B\r\n",
			want:   true,
		},
		{
			name:   "valid fix on a later line",
			output: "\xb5\x62\x01\x07\x00\x00\n$GNRMC,194845.00,A,3553.86724,N,07852.73886,W,0.000,,111126,,,A,V*0A\n",
			want:   true,
		},
		{
			name:   "no fix",
			output: "$GNRMC,194844.00,V,,,,,,,111126,,,N,V*1C\r\n",
			want:   false,
		},
		{
			name:   "binary records only",
			output: "\xb5\x62\x01\x07\x00\x00\x0a\x00",
			want:   false,
		},
		{
			name:   "empty output",
			output: "",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := HasValidFix(tt.output); got != tt.want {
				t.Fatalf("HasValidFix() = %v, want %v", got, tt.want)
			}
		})
	}
}

func runGNRMCCommand(t *testing.T, data []byte) string {
	t.Helper()
	if _, err := exec.LookPath("timeout"); err != nil {
		t.Skip("timeout command not available")
	}
	dev := filepath.Join(t.TempDir(), "gnss0")
	if err := os.WriteFile(dev, data, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", "-c", GNRMCSentenceCommand(dev)).Output() //nolint:gosec // dev is a fixture inside t.TempDir(), not untrusted input
	if err != nil {
		t.Fatalf("running GNSS command: %v", err)
	}
	return string(out)
}

func TestGNRMCSentenceCommandScansPastBinaryRecords(t *testing.T) {
	data := []byte{0xb5, 0x62, 0x01, 0x07, 0x00, 0x00, 0x0a, 0x00, 0xde, 0xad, 0xbe, 0xef, '\n'}
	data = append(data, []byte("$GNRMC,194844.00,A,3553.86724,N,07852.73886,W,0.000,,111126,,,A,V*0B\r\n")...)

	if out := runGNRMCCommand(t, data); !HasValidFix(out) {
		t.Fatalf("HasValidFix(%q) = false, want true when NMEA follows UBX binary records", out)
	}
}

func TestGNRMCSentenceCommandRejectsMissingFix(t *testing.T) {
	data := []byte("$GNRMC,194844.00,V,,,,,,,111126,,,N,V*1C\r\n")

	if out := runGNRMCCommand(t, data); HasValidFix(out) {
		t.Fatalf("HasValidFix(%q) = true, want false without a valid fix", out)
	}
}
