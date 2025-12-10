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
func main() {
	const (
		// problem/scenario name
		findOCProblemName = "OC"

		// unique id for each tag, e.g. solution role
		tagSlave       = 0
		tagGrandmaster = 1
	)

	if1 := exports.PtpIf{
		IfClusterIndex: exports.IfClusterIndex{InterfaceName: "ens3f0", NodeName: "node1"},
		Iface:          exports.Iface{IfName: "ens3f0", IfMac: exports.Mac{Data: "52:55:00:81:c2:62"}, IfPci: exports.PCIAddress{Device: "00:03", Function: "0"}},
	}
	if2 := exports.PtpIf{
		IfClusterIndex: exports.IfClusterIndex{InterfaceName: "ens3f0", NodeName: "node2"},
		Iface:          exports.Iface{IfName: "ens3f0", IfMac: exports.Mac{Data: "52:55:00:81:c2:63"}, IfPci: exports.PCIAddress{Device: "00:03", Function: "0"}},
	}
	lans := [][]int{{0, 1}}
	aGraph := testGraph{ifList: []*exports.PtpIf{&if1, &if2}, lans: &lans, ptpInterfaces: nil}

	// initialize L2 config in solver
	graphsolver.GlobalConfig.SetL2Config(&aGraph)

	// Initializing problems
	graphsolver.GlobalConfig.InitProblem(
		findOCProblemName,
		[][][]int{
			{{int(graphsolver.StepNil), 0, 0}},         // step1
			{{int(graphsolver.StepSameLan2), 2, 0, 1}}, // step2
		},
		[]int{tagSlave: 0, tagGrandmaster: 1},
	)

	// Run solver for problem
	graphsolver.GlobalConfig.Run(findOCProblemName)

	// print first solution
	graphsolver.GlobalConfig.PrintAllSolutions()
}
