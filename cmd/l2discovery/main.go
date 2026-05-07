//go:build linux

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe" //nolint:gocritic

	"github.com/kelseyhightower/envconfig"
	"github.com/redhat-cne/l2discovery-lib/exports"
	"github.com/redhat-cne/l2discovery-lib/pkg/parser"
	"github.com/sirupsen/logrus"
)

/*
#include <stdint.h>
#include <stdlib.h>
#include <linux/if_packet.h>
#include <sys/socket.h>
#include <string.h>
#include <arpa/inet.h>

typedef struct __attribute__((packed))
{
    char dest[6];
    char sender[6];
    uint16_t protocolType;
} EthernetHeader;

char* CreateProbe(char* senderMac)
{
    EthernetHeader * packet = malloc(sizeof(EthernetHeader));
    memset(packet, 0, sizeof(EthernetHeader));
    // Ethernet header
    // Dest = Broadcast (ff:ff:ff:ff:ff)
    packet->dest[0] = 0xff;
    packet->dest[1] = 0xff;
    packet->dest[2] = 0xff;
    packet->dest[3] = 0xff;
    packet->dest[4] = 0xff;
    packet->dest[5] = 0xff;

    packet->sender[0] = strtol(senderMac, NULL, 16); senderMac += 3;
    packet->sender[1] = strtol(senderMac, NULL, 16); senderMac += 3;
    packet->sender[2] = strtol(senderMac, NULL, 16); senderMac += 3;
    packet->sender[3] = strtol(senderMac, NULL, 16); senderMac += 3;
    packet->sender[4] = strtol(senderMac, NULL, 16); senderMac += 3;
    packet->sender[5] = strtol(senderMac, NULL, 16);

    packet->protocolType = htons(0x88B5); // local experimental ethertype

    return (char*) packet;
}

int IfaceBind(int fd, int ifindex)
{
	struct sockaddr_ll	sll;
    struct packet_mreq mreq;

	memset(&sll, 0, sizeof(sll));
	memset(&mreq,0,sizeof(mreq));

	sll.sll_family		= AF_PACKET;
	sll.sll_ifindex		= ifindex < 0 ? 0 : ifindex;
	sll.sll_protocol	= 0;

	if (bind(fd, (struct sockaddr *) &sll, sizeof(sll)) == -1) {
		return 1;
	}

	// promiscuous mode needed for PTP
	mreq.mr_ifindex = ifindex;
	mreq.mr_type = PACKET_MR_PROMISC;
	mreq.mr_alen = 6;

	if (setsockopt(fd,SOL_PACKET,PACKET_ADD_MEMBERSHIP,
		(void*)&mreq,(socklen_t)sizeof(mreq)) < 0)
			return -3;
    return 0;
}
*/
import "C" //nolint:gocritic

const (
	bondSlave    = "bond"
	chrootPrefix = "chroot /host /usr/sbin/"
)

var PCIMap map[string]exports.PCIAddress

type config struct {
	AllIFs           bool `default:"false"`
	UseContainerCmds bool `default:"false"`
}

type ipOut struct {
	Ifindex          int           `json:"ifindex"`
	Ifname           string        `json:"ifname"`
	Flags            []string      `json:"flags"`
	Mtu              int           `json:"mtu"`
	Qdisc            string        `json:"qdisc"`
	Operstate        string        `json:"operstate"`
	Linkmode         string        `json:"linkmode"`
	Group            string        `json:"group"`
	Txqlen           int           `json:"txqlen,omitempty"`
	LinkType         string        `json:"link_type"`
	Address          string        `json:"address"`
	Broadcast        string        `json:"broadcast"`
	Promiscuity      int           `json:"promiscuity"`
	MinMtu           int           `json:"min_mtu"`
	MaxMtu           int           `json:"max_mtu"`
	Inet6AddrGenMode string        `json:"inet6_addr_gen_mode"`
	NumTxQueues      int           `json:"num_tx_queues"`
	NumRxQueues      int           `json:"num_rx_queues"`
	GsoMaxSize       int           `json:"gso_max_size"`
	GsoMaxSegs       int           `json:"gso_max_segs"`
	PhysPortName     string        `json:"phys_port_name,omitempty"`
	PhysSwitchID     string        `json:"phys_switch_id,omitempty"`
	VfinfoList       []interface{} `json:"vfinfo_list,omitempty"`
	PhysPortID       string        `json:"phys_port_id,omitempty"`
	Master           string        `json:"master,omitempty"`
	Linkinfo         struct {
		InfoSlaveKind string `json:"info_slave_kind"`
		InfoKind      string `json:"info_kind"`
		InfoSlaveData struct {
			State     string `json:"state"`
			MiiStatus string `json:"mii_status"`
		} `json:"info_slave_data"`
	} `json:"linkinfo,omitempty"`
	LinkIndex   int `json:"link_index,omitempty"`
	LinkNetnsid int `json:"link_netnsid,omitempty"`
}

type Frame struct {
	MacDa exports.Mac
	MacSa exports.Mac
	Type  string
}

var (
	MacsPerIface map[string]map[string]*exports.Neighbors
	mu           sync.Mutex
)

func (frame *Frame) parse(rawFrame []byte) {
	frame.MacDa.Data = hex.EncodeToString(rawFrame[0:6])
	frame.MacSa.Data = hex.EncodeToString(rawFrame[6:12])
	frame.Type = hex.EncodeToString(rawFrame[12:14])
}
func (frame *Frame) String() string {
	return fmt.Sprintf("DA=%s SA=%s TYPE=%s", frame.MacDa, frame.MacSa, frame.Type)
}

// PTP Announce message offsets from start of PTP header.
// PTP common header is 34 bytes, announce body is 30 bytes.
const (
	ptpMessageTypeAnnounce = 0x0B
	ptpPtpHeaderSize       = 34
	ptpAnnounceBodySize    = 30
	ptpMinAnnouncePayload  = ptpPtpHeaderSize + ptpAnnounceBodySize

	// Offsets from start of PTP header
	ptpOffsetMessageType            = 0
	ptpOffsetDomainNumber           = 4
	ptpOffsetGrandmasterPriority1   = 47
	ptpOffsetClockClass             = 48
	ptpOffsetClockAccuracy          = 49
	ptpOffsetOffsetScaledLogVar     = 50
	ptpOffsetGrandmasterPriority2   = 52
	ptpOffsetGrandmasterIdentity    = 53
	ptpOffsetGrandmasterIdentityEnd = 61
	ptpOffsetStepsRemoved           = 61
	ptpOffsetTimeSource             = 63
)

// ethernetHeaderLen returns the length of the Ethernet header, accounting for VLAN tags.
// Returns ok=false if the frame is too short to parse.
func ethernetHeaderLen(rawFrame []byte) (headerLen int, ok bool) {
	if len(rawFrame) < 14 {
		return 0, false
	}
	headerLen = 14
	offset := 12
	ethType := binary.BigEndian.Uint16(rawFrame[offset : offset+2])
	for ethType == 0x8100 || ethType == 0x88a8 {
		// VLAN tag adds 4 bytes (TPID + TCI)
		if len(rawFrame) < headerLen+4 {
			return 0, false
		}
		headerLen += 4
		offset += 4
		if len(rawFrame) < offset+2 {
			return 0, false
		}
		ethType = binary.BigEndian.Uint16(rawFrame[offset : offset+2])
	}
	return headerLen, true
}

// parsePtpAnnounce decodes a PTP Announce message from a raw Ethernet frame.
// Returns nil if the frame is not a PTP Announce message or is too short.
func parsePtpAnnounce(rawFrame []byte) *exports.PtpAnnounceData {
	ethHeaderLen, ok := ethernetHeaderLen(rawFrame)
	if !ok {
		return nil
	}
	if len(rawFrame) < ethHeaderLen+ptpMinAnnouncePayload {
		return nil
	}
	// Check message type (lower nibble of first PTP byte)
	base := ethHeaderLen
	messageType := rawFrame[base+ptpOffsetMessageType] & 0x0F
	if messageType != ptpMessageTypeAnnounce {
		return nil
	}

	announce := &exports.PtpAnnounceData{
		DomainNumber:            rawFrame[base+ptpOffsetDomainNumber],
		GrandmasterPriority1:    rawFrame[base+ptpOffsetGrandmasterPriority1],
		ClockClass:              rawFrame[base+ptpOffsetClockClass],
		ClockAccuracy:           rawFrame[base+ptpOffsetClockAccuracy],
		OffsetScaledLogVariance: binary.BigEndian.Uint16(rawFrame[base+ptpOffsetOffsetScaledLogVar : base+ptpOffsetOffsetScaledLogVar+2]),
		GrandmasterPriority2:    rawFrame[base+ptpOffsetGrandmasterPriority2],
		GrandmasterIdentity:     hex.EncodeToString(rawFrame[base+ptpOffsetGrandmasterIdentity : base+ptpOffsetGrandmasterIdentityEnd]),
		StepsRemoved:            binary.BigEndian.Uint16(rawFrame[base+ptpOffsetStepsRemoved : base+ptpOffsetStepsRemoved+2]),
		TimeSource:              rawFrame[base+ptpOffsetTimeSource],
	}
	logrus.Debugf("Parsed PTP Announce: %s", announce)
	return announce
}

func runLocalCommand(command string) (outStr, errStr string, err error) {
	const chrootHost = "chroot /host "
	if strings.Contains(command, chrootHost) {
		noChroot, found := strings.CutPrefix(command, chrootHost)
		if !found {
			return outStr, errStr, fmt.Errorf("failed to find chroot prefix in command")
		}
		command = noChroot
	}
	cmd := exec.Command("sh", "-c", command)
	if strings.Contains(command, chrootHost) {
		cmd.SysProcAttr = &syscall.SysProcAttr{
			Chroot: "/host",
			// ensure we stay as root
			Credential: &syscall.Credential{Uid: 0, Gid: 0},
		}
	}

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	if err != nil {
		return "", "", err
	}
	outStr, errStr = stdout.String(), stderr.String()
	logrus.Tracef("Command %s, STDERR: %s, STDOUT: %s", cmd.String(), errStr, outStr)
	return outStr, errStr, err
}

func main() {
	cfg := config{}
	err := envconfig.Process("l2discovery", &cfg)
	if err != nil {
		logrus.Fatal(err.Error())
	}
	cmdPrefix := chrootPrefix
	if cfg.UseContainerCmds {
		cmdPrefix = ""
	}
	logrus.SetFormatter(&logrus.TextFormatter{DisableColors: true})
	logrus.SetLevel(logrus.InfoLevel)

	err = initPCIMap(cmdPrefix)
	if err != nil {
		logrus.Fatalf("could not initialize PCIMap, err: %s", err)
	}
	logrus.Infof("PCIMap: %+v", PCIMap)
	macs, macExist, err := getIfs(cfg, cmdPrefix)
	if err != nil {
		logrus.Fatalf("could not get Local interfaces, err: %s", err)
	}
	MacsPerIface = make(map[string]map[string]*exports.Neighbors)
	for _, iface := range macs {
		RecordAllLocal(iface)
		go RecvFrame(iface, macExist)
		if iface.IfSlaveType != bondSlave {
			go sendProbeForever(iface)
		}
	}
	go PrintLog()
	select {}
}

func sendProbe(iface *exports.Iface) {
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	defer syscall.Close(fd)
	if err != nil {
		logrus.Errorf("Error: %s", err)
		return
	}
	// for Link aggregation interfaces, use the link aggregated interface to send the probe packets
	// The bond interface will carry it in a way so as to not generate traffic loops. As a result,
	// only the primary port, responsible to carry broadcast and multicast traffic will be discovered by
	// l2discovery
	senderIface := iface.IfName
	if iface.IfSlaveType == bondSlave {
		senderIface = iface.IfMaster
	}

	err = syscall.BindToDevice(fd, senderIface)
	if err != nil {
		panic(err)
	}
	C.IfaceBind(C.int(fd), C.int(iface.IfIndex))
	ether := new(C.EthernetHeader)
	size := uint(unsafe.Sizeof(*ether))
	logrus.Tracef("Size : %d", size)
	interf, err := net.InterfaceByName(senderIface)
	if err != nil {
		logrus.Errorf("Could not find %s interface", senderIface)
		return
	}
	logrus.Tracef("Interface hw address: %s", iface.IfMac)

	ifaceCstr := C.CString(iface.IfMac.Data)

	packet := C.GoBytes(unsafe.Pointer(C.CreateProbe(ifaceCstr)), C.int(size))

	// Send the packet
	var addr syscall.SockaddrLinklayer
	addr.Protocol = syscall.ETH_P_ARP
	addr.Ifindex = interf.Index
	addr.Hatype = syscall.ARPHRD_ETHER
	err = syscall.Sendto(fd, packet, 0, &addr)

	if err != nil {
		logrus.Errorf("error: %s", err)
	}
	logrus.Tracef("Sent packet")
}

func RecvFrame(iface *exports.Iface, macsExist map[string]bool) {
	const (
		recvTimeout           = 2
		recvBufferSize        = 1024
		experimentalEthertype = "88b5"
		ptpEthertype          = "88f7"
		allEthPacketTypes     = 0x0300
	)
	time.Sleep(time.Second * recvTimeout)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, allEthPacketTypes)
	defer syscall.Close(fd)
	if err != nil {
		syscall.Close(fd)
		panic(err)
	}

	C.IfaceBind(C.int(fd), C.int(iface.IfIndex))

	data := make([]byte, recvBufferSize)
	for {
		_, _, err := syscall.Recvfrom(fd, data, 0)
		if err != nil {
			continue
		}
		var aFrame Frame
		aFrame.parse(data)
		mu.Lock()
		// only processes experimental and ptp frames
		if strings.EqualFold(aFrame.Type, experimentalEthertype) || strings.EqualFold(aFrame.Type, ptpEthertype) {
			if _, ok := macsExist[strings.ToUpper(aFrame.MacSa.String())]; !ok {
				if _, ok := MacsPerIface[aFrame.Type]; !ok {
					MacsPerIface[aFrame.Type] = make(map[string]*exports.Neighbors)
				}
				if _, ok := MacsPerIface[aFrame.Type][iface.IfName]; !ok {
					aNeighbors := exports.Neighbors{Local: *iface, Remote: make(map[string]bool)}
					MacsPerIface[aFrame.Type][iface.IfName] = &aNeighbors
				}
				if MacsPerIface[aFrame.Type][iface.IfName].Local.IfMac != aFrame.MacSa {
					MacsPerIface[aFrame.Type][iface.IfName].Remote[aFrame.MacSa.String()] = true
				}
			}
			// For PTP frames, try to decode the Announce message
			if strings.EqualFold(aFrame.Type, ptpEthertype) {
				if announce := parsePtpAnnounce(data); announce != nil {
					if _, ok := MacsPerIface[aFrame.Type]; ok {
						if neighbor, ok := MacsPerIface[aFrame.Type][iface.IfName]; ok {
							if neighbor.PtpAnnounces == nil {
								neighbor.PtpAnnounces = make(map[string]*exports.PtpAnnounceData)
							}
							// Store per GM identity; latest announce from each GM wins
							neighbor.PtpAnnounces[announce.GrandmasterIdentity] = announce
						}
					}
				}
			}
		}
		mu.Unlock()
	}
}

func RecordAllLocal(iface *exports.Iface) {
	const (
		localInterfaces = "0000"
	)
	mu.Lock()
	if _, ok := MacsPerIface[localInterfaces]; !ok {
		MacsPerIface[localInterfaces] = make(map[string]*exports.Neighbors)
	}
	if _, ok := MacsPerIface[localInterfaces][iface.IfName]; !ok {
		aNeighbors := exports.Neighbors{Local: *iface, Remote: make(map[string]bool)}
		MacsPerIface[localInterfaces][iface.IfName] = &aNeighbors
	}
	mu.Unlock()
}

func PrintLog() {
	const logPrintPeriod = 5 // in seconds
	for {
		mu.Lock()
		aString, err := json.Marshal(MacsPerIface)
		if err != nil {
			logrus.Errorf("Cannot marshall MacsPerIface")
		}
		// Only log printed
		fmt.Printf("JSON_REPORT%s\n", string(aString))
		mu.Unlock()
		time.Sleep(time.Second * logPrintPeriod)
	}
}

func sendProbeForever(iface *exports.Iface) {
	// sending probe frames mess with link aggregation. After sending a maximum number of probes for a given
	// interface, stop forever. Discovery should be complete by then.
	const maxProbes = 10
	for i := 0; i < maxProbes; i++ {
		time.Sleep(time.Second * 1)
		sendProbe(iface)
	}
}

func getIfs(cfg config, cmdPrefix string) (macs map[string]*exports.Iface, macsExist map[string]bool, err error) {
	const (
		ifCommand = "ip -details -json link show"
	)
	stdout, stderr, err := runLocalCommand(cmdPrefix + ifCommand)
	if err != nil || stderr != "" {
		return macs, macsExist, fmt.Errorf(
			"could not execute ip command(%s), err=%s stderr=%s",
			cmdPrefix+ifCommand,
			err,
			stderr,
		)
	}
	macs = make(map[string]*exports.Iface)
	macsExist = make(map[string]bool)
	aIPOut := []*ipOut{}
	err = json.Unmarshal([]byte(stdout), &aIPOut)
	if err != nil {
		return macs, macsExist, err
	}
	for _, aIfRaw := range aIPOut {
		if aIfRaw.LinkType == "loopback" ||
			(aIfRaw.Linkinfo.InfoKind != "" && !cfg.AllIFs) {
			continue
		}
		var address exports.PCIAddress
		address, err = getPci(aIfRaw.Ifname, cmdPrefix)
		if err != nil {
			logrus.Warnf("could not get PCI info err: %s", err)
		}
		var ptpCaps exports.PTPCaps
		ptpCaps, err = getPtpCaps(aIfRaw.Ifname, cmdPrefix, runLocalCommand)
		if err != nil {
			return macs, macsExist, fmt.Errorf("could not get PTP capabilities info err: %s", err)
		}
		ptpCaps.HasPtpPins = hasPtpPins(aIfRaw.Ifname, ptpCaps.PhcIndex, cmdPrefix)
		ptpCaps.GnssDevice = getGnssDevice(aIfRaw.Ifname, cmdPrefix)
		aIface := exports.Iface{
			IfName:      aIfRaw.Ifname,
			IfMac:       exports.Mac{Data: strings.ToUpper(aIfRaw.Address)},
			IfIndex:     aIfRaw.Ifindex,
			IfPci:       address,
			IfPTPCaps:   ptpCaps,
			IfUp:        aIfRaw.Operstate == "UP",
			IfMaster:    aIfRaw.Master,
			IfSlaveType: aIfRaw.Linkinfo.InfoSlaveKind,
		}
		macs[aIfRaw.Ifname] = &aIface
		macsExist[strings.ToUpper(aIfRaw.Address)] = true
	}
	return macs, macsExist, nil
}

func getPci(ifaceName, cmdPrefix string) (aPciAddress exports.PCIAddress, err error) {
	const (
		ethtoolBaseCommand = "ethtool -i"
	)
	aCommand := fmt.Sprintf("%s %s", cmdPrefix+ethtoolBaseCommand, ifaceName)
	stdout, stderr, err := runLocalCommand(aCommand)
	if err != nil || stderr != "" {
		return aPciAddress, fmt.Errorf(
			"could not execute ethtool command(%s), err=%s stderr=%s",
			aCommand,
			err,
			stderr,
		)
	}
	var address, function string
	address, function, err = parser.ParseEthtool(stdout)
	if err != nil {
		return aPciAddress, fmt.Errorf("could not parse output of ethtool command, err=%s", err)
	}
	var ok bool
	if aPciAddress, ok = PCIMap[address+"."+function]; !ok {
		return aPciAddress, fmt.Errorf("did not find PCI address: %s in PCIMap", address+"."+function)
	}
	return aPciAddress, nil
}

func initPCIMap(cmdPrefix string) error {
	const lscpiCommand = "lspci -vv -D"
	stdout, stderr, err := runLocalCommand(cmdPrefix + lscpiCommand)
	if strings.Contains(stderr, "kmod") {
		logrus.Warnf("lspci returns kmod error, output should still be usable")
	}
	if err != nil || stderr != "" && !strings.Contains(stderr, "kmod") {
		return fmt.Errorf(
			"could not execute lspci command(%s), err=%s stderr=%s",
			cmdPrefix+lscpiCommand,
			err,
			stderr,
		)
	}
	PCIMap, err = parser.ParseLspci(stdout)
	if err != nil {
		return fmt.Errorf("could not parse output of lspci to create PCI Map")
	}
	return nil
}

func getPtpCaps(
	ifaceName, cmdPrefix string,
	runCmd func(command string) (outStr, errStr string, err error),
) (aPTPCaps exports.PTPCaps, err error) {
	const (
		ethtoolBaseCommand = "ethtool -T "
		hwTxString         = "hardware-transmit"
		hwRxString         = "hardware-receive"
		hwRawClock         = "hardware-raw-clock"
	)
	aPTPCaps.PhcIndex = -1

	aCommand := cmdPrefix + ethtoolBaseCommand + ifaceName
	stdout, stderr, err := runCmd(aCommand)
	if err != nil || stderr != "" {
		return aPTPCaps, fmt.Errorf("could not execute "+aCommand+" command, err=%s stderr=%s", err, stderr)
	}

	r := regexp.MustCompile(`(?m)(` + hwTxString + `)|(` + hwRxString + `)|(` + hwRawClock + `)$`)
	for _, submatches := range r.FindAllStringSubmatchIndex(stdout, -1) {
		aString := string(r.ExpandString([]byte{}, "$1", stdout, submatches))
		if !aPTPCaps.HwTx {
			aPTPCaps.HwTx = aString == hwTxString
		}

		aString = string(r.ExpandString([]byte{}, "$2", stdout, submatches))
		if !aPTPCaps.HwRx {
			aPTPCaps.HwRx = aString == hwRxString
		}

		aString = string(r.ExpandString([]byte{}, "$3", stdout, submatches))
		if !aPTPCaps.HwRawClock {
			aPTPCaps.HwRawClock = aString == hwRawClock
		}
	}

	phcRe := regexp.MustCompile(`(?m)PTP Hardware Clock:\s+(\S+)`)
	if matches := phcRe.FindStringSubmatch(stdout); len(matches) > 1 {
		if !strings.EqualFold(matches[1], "none") {
			if idx, parseErr := strconv.Atoi(matches[1]); parseErr == nil {
				aPTPCaps.PhcIndex = idx
			}
		}
	}

	return aPTPCaps, nil
}

func hasPtpPins(ifaceName string, phcIndex int, cmdPrefix string) bool {
	if phcIndex < 0 {
		return false
	}
	path := fmt.Sprintf("/sys/class/net/%s/device/ptp/ptp%d/pins", ifaceName, phcIndex)
	cmd := fmt.Sprintf("%sls -d %s 2>/dev/null", cmdPrefix, path)
	stdout, _, err := runLocalCommand(cmd)
	return err == nil && strings.TrimSpace(stdout) != ""
}

func getGnssDevice(ifaceName, cmdPrefix string) string {
	path := fmt.Sprintf("/sys/class/net/%s/device/gnss", ifaceName)
	cmd := fmt.Sprintf("%sls %s 2>/dev/null", cmdPrefix, path)
	stdout, _, err := runLocalCommand(cmd)
	if err != nil || strings.TrimSpace(stdout) == "" {
		return ""
	}
	for _, dev := range strings.Split(strings.TrimSpace(stdout), "\n") {
		if dev != "" && checkGNRMC(dev, cmdPrefix) {
			return dev
		}
	}
	return ""
}

func checkGNRMC(deviceName, cmdPrefix string) bool {
	cmd := fmt.Sprintf("%shead -n 1 /dev/%s", cmdPrefix, strings.TrimSpace(deviceName))
	stdout, _, err := runLocalCommand(cmd)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, "GNRMC") {
			parts := strings.Split(line, ",")
			if len(parts) > 1 {
				timeVal := parts[1]
				formattedTime := time.Now().UTC().Format("150405") + ".00"
				if strings.EqualFold(timeVal, formattedTime) {
					return true
				}
			}
		}
	}
	return false
}
