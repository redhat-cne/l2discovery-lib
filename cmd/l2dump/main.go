package main

import (
	"bytes"
	"fmt"

	"github.com/goccy/go-graphviz"
	"github.com/goccy/go-graphviz/cgraph"
	"github.com/openshift/ptp-operator/test/pkg/client"
	l2lib "github.com/redhat-cne/l2discovery-lib"
	"github.com/redhat-cne/l2discovery-lib/exports"
	"github.com/sirupsen/logrus"
)

var colors = []string{"aqua", "aquamarine", "bisque", "chartreuse", "cornflowerblue", "fuchsia", "yellow", "teal"}

func main() {
	client.Client = client.New("")
	l2lib.GlobalL2DiscoveryConfig.SetL2Client(client.Client, client.Client.Config)
	l2info, err := l2lib.GlobalL2DiscoveryConfig.GetL2DiscoveryConfig(false, true, true, "quay.io/redhat-cne/l2discovery:latest")
	if err != nil {
		logrus.Fatalf("could not get l2 info because: %s", err)
	}
	getGraph(l2info)
}

//nolint:funlen
func getGraph(data l2lib.L2Info) {
	g := graphviz.New()
	mainGraph, err := g.Graph()
	if err != nil {
		logrus.Fatal(err)
	}

	defer func() {
		if err := mainGraph.Close(); err != nil {
			logrus.Fatal(err)
		}
		if err := g.Close(); err != nil {
			logrus.Fatal(err)
		}
	}()
	nodes := make(map[string]bool)
	for _, lan := range *data.GetLANs() {
		for _, i := range lan {
			nodes[data.GetPtpIfList()[i].NodeName] = true
		}
	}

	subGraphs := make(map[string]*cgraph.Graph)
	i := 0
	for n := range nodes {
		i++
		subGraphs[n] = mainGraph.SubGraph("cluster_"+n, i)
		subGraphs[n].SetLabel(n)
		subGraphs[n].SetColorScheme("svg")
		subGraphs[n].SetBackgroundColor("silver")
	}

	var lans []*cgraph.Node
	k := 0
	for _, lan := range *data.GetLANs() {
		if len(lan) == 1 {
			continue
		}
		aColor := colors[k]
		if k > len(colors) {
			aColor = "skyblue"
			logrus.Warnf("Number of LANs (%d) exceeding the number of colors(%d), please update colors structure. All extra LANs will be the same color skyblue", k, len(colors))
		}
		nodes := make(map[exports.IfClusterIndex]*cgraph.Node)
		aLan, err := mainGraph.CreateNode(fmt.Sprintf("LAN%d", k))
		aLan.SetColorScheme("svg")
		aLan.SetStyle("filled")
		aLan.SetColor(aColor)
		lans = append(lans, aLan)
		if err != nil {
			logrus.Fatal(err)
		}
		for _, i := range lan {
			aIf := data.GetPtpIfList()[i]
			nodes[aIf.IfClusterIndex], err = subGraphs[aIf.NodeName].CreateNode(aIf.IfClusterIndex.String())
			if err != nil {
				logrus.Fatal(err)
			}
			nodes[aIf.IfClusterIndex].SetLabel(aIf.InterfaceName)
			nodes[aIf.IfClusterIndex].SetColorScheme("svg")
			nodes[aIf.IfClusterIndex].SetStyle("filled")
			nodes[aIf.IfClusterIndex].SetColor(aColor)

			index := data.GetPtpIfList()[i].IfClusterIndex
			edge, err := mainGraph.CreateEdge("", nodes[index], lans[k])
			if err != nil {
				logrus.Fatal(err)
			}
			edge.SetColorScheme("svg")
			edge.SetColor(aColor)
		}
		k++
	}

	var buf bytes.Buffer
	if err := g.Render(mainGraph, "dot", &buf); err != nil {
		logrus.Fatal(err)
	}
	fmt.Println(buf.String())
}
