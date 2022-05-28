package internal

import (
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket/pcap"
)

func GetBpfFilter(srcHost string, dstHost string, srcPort int, dstPort int) (filter string) {
	var bpfFilters []string
	if len(srcHost) > 0 {
		bpfFilters = append(bpfFilters, "src host "+srcHost)
	}
	if len(dstHost) > 0 {
		bpfFilters = append(bpfFilters, "dst host "+dstHost)
	}
	if srcPort > 0 && srcPort <= 65535 {
		bpfFilters = append(bpfFilters, "src port "+strconv.Itoa(srcPort))
	}
	if dstPort > 0 && dstPort <= 65535 {
		bpfFilters = append(bpfFilters, "dst port "+strconv.Itoa(dstPort))
	}
	return strings.Join(bpfFilters, " and ")
}

func GetPcapListener(interf *pcap.Interface, filter string) (handle *pcap.Handle, err error) {
	handle, err = pcap.OpenLive(interf.Name, int32(65535), true, -1*time.Second)
	if err != nil {
		return
	}
	err = handle.SetBPFFilter(filter)
	return
}
