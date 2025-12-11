package main

import (
	"github.com/openshift/ptp-operator/test/pkg/client"
	l2lib "github.com/redhat-cne/l2discovery-lib"
	"github.com/redhat-cne/l2discovery-lib/pkg/graphsolver"
)

// Runs Solver to find optimal configurations
func main() {
	const (
		// problem/scenario name
		findOCProblemName = "interfaces connected via a LAN"

		// unique id for each tag, e.g. solution role
		tagSlave       = 0
		tagGrandmaster = 1
	)

	// create an OC client
	client.Client = client.New("")

	// Initialize l2 library
	l2lib.GlobalL2DiscoveryConfig.SetL2Client(client.Client, client.Client.Config)

	// Collect L2 info
	config, err := l2lib.GlobalL2DiscoveryConfig.GetL2DiscoveryConfig(false, true, true, "quay.io/redhat-cne/l2discovery:latest")
	if err != nil {
		return
	}

	// initialize L2 config in solver
	graphsolver.GlobalConfig.SetL2Config(config)

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
