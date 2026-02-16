package main

import (
	"github.com/redhat-cne/l2discovery-lib/exports"
	"github.com/redhat-cne/l2discovery-lib/pkg/graphsolver"
)

type testGraph struct {
	// list of cluster interfaces indexed with a simple integer (X) for readability in the graph
	ifList []*exports.PtpIf
	// LANs identified in the graph
	lans *[][]int
	// List of port receiving PTP frames (assuming valid GM signal received)
	ptpInterfaces []*exports.PtpIf
}

// list of cluster interfaces indexed with a simple integer (X) for readability in the graph
func (config testGraph) GetPtpIfList() []*exports.PtpIf {
	return config.ifList
}

// list of unfiltered cluster interfaces indexed with a simple integer (X) for readability in the graph
func (config testGraph) GetPtpIfListUnfiltered() map[string]*exports.PtpIf {
	return nil
}

// LANs identified in the graph
func (config testGraph) GetLANs() *[][]int {
	return config.lans
}

// List of port receiving PTP frames (assuming valid GM signal received)
func (config testGraph) GetPortsGettingPTP() []*exports.PtpIf {
	return config.ptpInterfaces
}

// Runs Solver to find optimal configurations
//
//nolint:funlen // example program, splitting would hurt readability
func main() {
	const (
		// problem/scenario names
		findOCProblemName     = "OC"
		filteredOCProblemName = "filtered-OC"

		// unique id for each tag, e.g. solution role
		tagSlave       = 0
		tagGrandmaster = 1
	)

	// Simulate PTP Announce data received from two different grandmasters.
	// GM1: domain 24, clock class 6 (locked to GPS)
	gm1 := &exports.PtpAnnounceData{
		DomainNumber:         24,
		GrandmasterPriority1: 128,
		ClockClass:           6,
		ClockAccuracy:        0x21,
		GrandmasterPriority2: 128,
		GrandmasterIdentity:  "001b19fffe010203",
		StepsRemoved:         0,
		TimeSource:           0x20,
	}
	// GM2: domain 0, clock class 248 (freerun)
	gm2 := &exports.PtpAnnounceData{
		DomainNumber:         0,
		GrandmasterPriority1: 128,
		ClockClass:           248,
		ClockAccuracy:        0xFE,
		GrandmasterPriority2: 128,
		GrandmasterIdentity:  "aabbccfffe112233",
		StepsRemoved:         0,
		TimeSource:           0xA0,
	}

	// Both interfaces see both GMs (they are on the same LAN)
	announces := map[string]*exports.PtpAnnounceData{
		gm1.GrandmasterIdentity: gm1,
		gm2.GrandmasterIdentity: gm2,
	}

	if1 := exports.PtpIf{
		IfClusterIndex: exports.IfClusterIndex{InterfaceName: "ens3f0", NodeName: "node1"},
		Iface:          exports.Iface{IfName: "ens3f0", IfMac: exports.Mac{Data: "52:55:00:81:c2:62"}, IfPci: exports.PCIAddress{Device: "00:03", Function: "0"}},
		Announces:      announces,
	}
	if2 := exports.PtpIf{
		IfClusterIndex: exports.IfClusterIndex{InterfaceName: "ens3f0", NodeName: "node2"},
		Iface:          exports.Iface{IfName: "ens3f0", IfMac: exports.Mac{Data: "52:55:00:81:c2:63"}, IfPci: exports.PCIAddress{Device: "00:03", Function: "0"}},
		Announces:      announces,
	}
	lans := [][]int{{0, 1}}
	aGraph := testGraph{ifList: []*exports.PtpIf{&if1, &if2}, lans: &lans, ptpInterfaces: nil}

	// initialize L2 config in solver
	graphsolver.GlobalConfig.SetL2Config(&aGraph)

	// Problem 1: Basic OC - find two interfaces on the same LAN
	graphsolver.GlobalConfig.InitProblem(
		findOCProblemName,
		[][][]int{
			{{int(graphsolver.StepNil), 0, 0}},         // step1
			{{int(graphsolver.StepSameLan2), 2, 0, 1}}, // step2
		},
		[]int{tagSlave: 0, tagGrandmaster: 1},
	)

	// Problem 2: Filtered OC - find two interfaces on the same LAN with PTP domain 24
	// and clock class < 135 (i.e., a valid GM signal)
	graphsolver.GlobalConfig.InitProblem(
		filteredOCProblemName,
		[][][]int{
			{ // step1: first interface must have domain 24 and clock class < 135
				graphsolver.Step1V(graphsolver.StepPTPDomainEquals, 0, 24, graphsolver.Positive),     //nolint:mnd // PTP domain 24
				graphsolver.Step1V(graphsolver.StepClockClassLessThan, 0, 135, graphsolver.Positive), //nolint:mnd // clock class < holdover
			},
			{ // step2: second interface on same LAN, also domain 24 and clock class < 135
				graphsolver.Step2(graphsolver.StepSameLan2, 0, 1, graphsolver.Positive),
				graphsolver.Step1V(graphsolver.StepPTPDomainEquals, 1, 24, graphsolver.Positive),     //nolint:mnd // PTP domain 24
				graphsolver.Step1V(graphsolver.StepClockClassLessThan, 1, 135, graphsolver.Positive), //nolint:mnd // clock class < holdover
			},
		},
		[]int{tagSlave: 0, tagGrandmaster: 1},
	)

	// Run solver for both problems
	graphsolver.GlobalConfig.Run(findOCProblemName)
	graphsolver.GlobalConfig.Run(filteredOCProblemName)

	// print all solutions
	graphsolver.GlobalConfig.PrintAllSolutions()
}
