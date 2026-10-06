package graphsolver

import (
	"testing"

	"github.com/redhat-cne/l2discovery-lib/exports"
)

type testL2Info struct {
	interfaces []*exports.PtpIf
}

func (c *testL2Info) GetPtpIfList() []*exports.PtpIf                    { return c.interfaces }
func (c *testL2Info) GetPtpIfListUnfiltered() map[string]*exports.PtpIf { return nil }
func (c *testL2Info) GetLANs() *[][]int                                 { return nil }
func (c *testL2Info) GetPortsGettingPTP() []*exports.PtpIf              { return nil }

func wpcInterface(node, name, device string, phc int, gnss string) *exports.PtpIf {
	return &exports.PtpIf{
		IfClusterIndex: exports.IfClusterIndex{NodeName: node, InterfaceName: name},
		Iface: exports.Iface{
			IfPci:     exports.PCIAddress{Device: device, Subsystem: WPCNICSubsystemID},
			IfPTPCaps: exports.PTPCaps{PhcIndex: phc, HasPtpPins: true, GnssDevice: gnss},
		},
	}
}

func TestTGMConstraintRequiresConnectedGNSSDevice(t *testing.T) {
	config := &testL2Info{interfaces: []*exports.PtpIf{
		wpcInterface("disconnected", "ens4f0", "0000:8a:00", 5, ""),
		wpcInterface("disconnected", "ens4f1", "0000:8a:00", 5, ""),
		wpcInterface("connected", "ens7f0", "0000:ca:00", 9, "gnss0"),
		wpcInterface("connected", "ens7f1", "0000:ca:00", 9, ""),
	}}
	problem := [][][]int{
		{{int(StepIsWPCNic), 1, 0}, {int(StepHasGNSSDevice), 1, 0}},
		{{int(StepIsWPCNic), 1, 1}, {int(StepSameNic), 2, 0, 1}},
	}

	GlobalConfig = configObject{}
	GlobalConfig.InitProblem("tgm", problem, []int{0, 1})
	GlobalConfig.SetL2Config(config)
	GlobalConfig.Run("tgm")

	solutions := *GlobalConfig.GetSolutions()["tgm"]
	if len(solutions) == 0 {
		t.Fatal("expected a T-GM solution")
	}
	for _, solution := range solutions {
		if solution[0] != 2 {
			t.Fatalf("selected interface %d without connected GNSS; solutions: %v", solution[0], solutions)
		}
	}
}
