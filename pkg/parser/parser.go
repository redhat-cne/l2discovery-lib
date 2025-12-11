package parser

import (
	"fmt"
	"regexp"

	"github.com/redhat-cne/l2discovery-lib/exports"
	"github.com/sirupsen/logrus"
)

func ParseLspci(output string) (aPCIMap map[string]exports.PCIAddress, err error) {
	const (
		regex          = `(?m)(\S*)\.(\d*)\s*(.*)$(.|\n)*?\s+(Subsystem:\s*(.*)$|\n)`
		expectedGroups = 7
	)
	// Compile the regular expression
	re := regexp.MustCompile(regex)

	// Find all matches
	matches := re.FindAllStringSubmatch(output, -1)

	if len(matches) < 1 {
		return aPCIMap, fmt.Errorf("could not parse lspci output")
	}

	aPCIMap = make(map[string]exports.PCIAddress)
	for index := range matches {
		var aPCI exports.PCIAddress
		if len(matches[index]) != expectedGroups {
			logrus.Warnf("wrong number of groups, could not match lspci output")
			continue
		}
		aPCI.Device = matches[index][1]
		aPCI.Function = matches[index][2]
		aPCI.Description = matches[index][3]
		aPCI.Subsystem = matches[index][6]

		aPCIMap[aPCI.Device+"."+aPCI.Function] = aPCI
	}

	return aPCIMap, nil
}

func ParseEthtool(output string) (pciDevice, pciFunction string, err error) {
	const (
		regex          = `(?m)bus-info: (.*)\.(\d+)$`
		expectedGroups = 3
	)

	// Compile the regular expression
	re := regexp.MustCompile(regex)

	// Find all matches
	matches := re.FindAllStringSubmatch(output, -1)

	if len(matches) < 1 {
		return pciDevice, pciFunction, fmt.Errorf(
			"could not parse ethtool output, no matches for PCI device and PCI function, output=%s",
			output,
		)
	}
	if len(matches[0]) < expectedGroups {
		return pciDevice, pciFunction, fmt.Errorf(
			"could not parse ethtool output, not enough groups returned, output=%s",
			output,
		)
	}

	pciDevice = matches[0][1]
	pciFunction = matches[0][2]

	return pciDevice, pciFunction, nil
}
