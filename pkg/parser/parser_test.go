package parser

import (
	"reflect"
	"testing"

	"github.com/redhat-cne/l2discovery-lib/exports"
)

func Test_parseEthtool(t *testing.T) {
	type args struct {
		output string
	}
	tests := []struct {
		name            string
		args            args
		wantPCIDevice   string
		wantPCIFunction string
		wantErr         bool
	}{
		{
			name: "ok",
			args: args{
				output: `driver: virtio_net
version: 1.0.0
firmware-version: 
expansion-rom-version: 
bus-info: 0000:01:00.0
supports-statistics: yes
supports-test: no
supports-eeprom-access: no
supports-register-dump: no
supports-priv-flags: no`,
			},
			wantPCIDevice:   "0000:01:00",
			wantPCIFunction: "0",
			wantErr:         false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPCIDevice, gotPCIFunction, err := ParseEthtool(tt.args.output)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseEthtool() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotPCIDevice != tt.wantPCIDevice {
				t.Errorf("parseEthtool() gotPCIDevice = %v, want %v", gotPCIDevice, tt.wantPCIDevice)
			}
			if gotPCIFunction != tt.wantPCIFunction {
				t.Errorf("parseEthtool() gotPCIFunction = %v, want %v", gotPCIFunction, tt.wantPCIFunction)
			}
		})
	}
}

//nolint:funlen
func TestParseLspci(t *testing.T) {
	type args struct {
		output string
	}
	tests := []struct {
		name        string
		args        args
		wantAPCIMap map[string]exports.PCIAddress
		wantErr     bool
	}{
		{
			name: "ok",
			args: args{
				output: `0000:05:00.0 Unclassified device [00ff]: Red Hat, Inc. Virtio 1.0 memory balloon (rev 01)
        Subsystem: Red Hat, Inc. Device 1100
        Physical Slot: 0-5
        Control: I/O+ Mem+ BusMaster+ SpecCycle- MemWINV- VGASnoop- ParErr- Stepping- SERR+ FastB2B- DisINTx-
        Status: Cap+ 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
        Latency: 0
        Interrupt: pin A routed to IRQ 22
        Region 4: Memory at fc400000 (64-bit, prefetchable) [size=16K]
        Capabilities: <access denied>
        Kernel driver in use: virtio-pci

0000:06:00.0 Unclassified device [00ff]: Red Hat, Inc. Virtio 1.0 RNG (rev 01)
        Subsystem: Red Hat, Inc. Device 1100
        Physical Slot: 0-6
        Control: I/O+ Mem+ BusMaster+ SpecCycle- MemWINV- VGASnoop- ParErr- Stepping- SERR+ FastB2B- DisINTx-
        Status: Cap+ 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
        Latency: 0
        Interrupt: pin A routed to IRQ 22
        Region 4: Memory at fc200000 (64-bit, prefetchable) [size=16K]
        Capabilities: <access denied>
        Kernel driver in use: virtio-pci

0000:04:00.0 Ethernet controller: Broadcom Inc. and subsidiaries NetXtreme BCM5720 Gigabit Ethernet PCIe
        DeviceName: Embedded NIC 1
        Subsystem: Dell PowerEdge Rx5xx LOM Board
        Control: I/O- Mem+ BusMaster+ SpecCycle- MemWINV- VGASnoop- ParErr- Stepping- SERR- FastB2B- DisINTx+
        Status: Cap+ 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
        Latency: 0
        Interrupt: pin A routed to IRQ 17
        NUMA node: 0
        IOMMU group: 14
        Region 0: Memory at 92930000 (64-bit, prefetchable) [size=64K]
        Region 2: Memory at 92940000 (64-bit, prefetchable) [size=64K]
        Region 4: Memory at 92950000 (64-bit, prefetchable) [size=64K]
        Expansion ROM at 90000000 [disabled] [size=256K]
        Capabilities: <access denied>
        Kernel driver in use: tg3
        Kernel modules: tg3

0000:00:1c.0 PCI bridge: Intel Corporation C620 Series Chipset Family PCI Express Root Port #1 (rev fa) (prog-if 00 [Normal decode])
	DeviceName: PCH Root Port
	Control: I/O+ Mem+ BusMaster+ SpecCycle- MemWINV- VGASnoop- ParErr+ Stepping- SERR+ FastB2B- DisINTx+
	Status: Cap+ 66MHz- UDF- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort- >SERR- <PERR- INTx-
	Latency: 0
	Interrupt: pin A routed to IRQ 130
	NUMA node: 0
	IOMMU group: 9
	Bus: primary=00, secondary=01, subordinate=01, sec-latency=0
	I/O behind bridge: [disabled]
	Memory behind bridge: [disabled]
	Prefetchable memory behind bridge: [disabled]
	Secondary status: 66MHz- FastB2B- ParErr- DEVSEL=fast >TAbort- <TAbort- <MAbort+ <SERR- <PERR-
	BridgeCtl: Parity+ SERR+ NoISA- VGA- VGA16- MAbort- >Reset- FastB2B-
		PriDiscTmr- SecDiscTmr- DiscTmrStat- DiscTmrSERREn-
	Capabilities: <access denied>
	Kernel driver in use: pcieport

`,
			},
			wantAPCIMap: map[string]exports.PCIAddress{
				"0000:05:00.0": {
					Device:      "0000:05:00",
					Function:    "0",
					Description: "Unclassified device [00ff]: Red Hat, Inc. Virtio 1.0 memory balloon (rev 01)",
					Subsystem:   "Red Hat, Inc. Device 1100"},
				"0000:06:00.0": {
					Device:      "0000:06:00",
					Function:    "0",
					Description: "Unclassified device [00ff]: Red Hat, Inc. Virtio 1.0 RNG (rev 01)",
					Subsystem:   "Red Hat, Inc. Device 1100"},
				"0000:04:00.0": {
					Device:      "0000:04:00",
					Function:    "0",
					Description: "Ethernet controller: Broadcom Inc. and subsidiaries NetXtreme BCM5720 Gigabit Ethernet PCIe",
					Subsystem:   "Dell PowerEdge Rx5xx LOM Board"},
				"0000:00:1c.0": {
					Device:      "0000:00:1c",
					Function:    "0",
					Description: "PCI bridge: Intel Corporation C620 Series Chipset Family PCI Express Root Port #1 (rev fa) (prog-if 00 [Normal decode])",
					Subsystem:   ""},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotAPCIMap, err := ParseLspci(tt.args.output)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseLspci() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(gotAPCIMap, tt.wantAPCIMap) {
				t.Errorf("ParseLspci() = %v, want %v", gotAPCIMap, tt.wantAPCIMap)
			}
		})
	}
}
