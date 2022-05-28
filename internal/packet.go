package internal

import (
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
)

func GetPcapFilters(srcHost string, dstHost string, srcPort int, dstPort int) (filter string) {
	var bpfFilters []string

	// We need to turn src and dst arround to get ACK packages
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
	filter = strings.Join(bpfFilters, " and ")
	log.Debugf("Created bpf filter \"%s\"", filter)
	return filter
}

func GetPcapHandleWithFilter(interf *pcap.Interface, filter string) (handle *pcap.Handle, err error) {
	handle, err = pcap.OpenLive(interf.Name, int32(65535), true, -1*time.Second)
	if err != nil {
		return
	}
	log.Debug("Adding bpf filter to pcap handle")
	err = handle.SetBPFFilter(filter)
	return
}

func ButcherConnections(packetSource *gopacket.PacketSource, handle *pcap.Handle) (err error) {
	rstPacketsCount := 3

	for packet := range packetSource.Packets() {
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer == nil {
			continue
		}
		eth := ethLayer.(*layers.Ethernet)

		ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
		ipv6Layer := packet.Layer(layers.LayerTypeIPv6)

		var ipVersion uint8
		if ipv4Layer == nil && ipv6Layer == nil {
			continue
		} else if ipv6Layer != nil {
			ipVersion = 6
		} else {
			ipVersion = 4
		}

		tcpLayer := packet.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}
		tcp := tcpLayer.(*layers.TCP)

		if tcp.SYN || tcp.FIN || tcp.RST {
			continue
		}

		for i := 0; i < rstPacketsCount; i++ {
			// seq := tcp.Ack + uint32(i)*uint32(tcp.Window)
			seq := tcp.Seq + uint32(i)*uint32(tcp.Window)

			var rstPacket gopacket.Packet
			if ipVersion == 4 {
				ip := ipv4Layer.(*layers.IPv4)
				rstPacket, err = ForgeIPv4RstPacket(eth.SrcMAC, eth.DstMAC, ip.SrcIP, ip.DstIP, tcp.SrcPort, tcp.DstPort, seq)
				// rstPacket, err = ForgeIPv4RstPacket(eth.DstMAC, eth.SrcMAC, ip.DstIP, ip.SrcIP, tcp.SrcPort, tcp.DstPort, seq)
			} else {
				ip := ipv6Layer.(*layers.IPv6)
				rstPacket, err = ForgeIPv6RstPacket(eth.SrcMAC, eth.DstMAC, ip.SrcIP, ip.DstIP, tcp.SrcPort, tcp.DstPort, seq)
				// rstPacket, err = ForgeIPv6RstPacket(eth.DstMAC, eth.SrcMAC, ip.DstIP, ip.SrcIP, tcp.SrcPort, tcp.DstPort, seq)
			}
			if err != nil {
				return err
			}
			log.Debug("Sending RST packet")
			err = handle.WritePacketData(rstPacket.Data())
			if err != nil {
				return err
			}
		}
	}
	return
}

func ForgeIPv4RstPacket(
	srcMac net.HardwareAddr,
	dstMac net.HardwareAddr,
	srcIp net.IP,
	dstIp net.IP,
	srcPort layers.TCPPort,
	dstPort layers.TCPPort,
	seq uint32,
) (packet gopacket.Packet, err error) {
	log.Debugf("Forging IPv4 RST Packet with seq \"%d\" from \"%s:%s\" to \"%s:%s\"",
		seq, srcIp.String(), srcPort.String(), dstIp.String(), dstPort.String())

	eth := getEthLayer(srcMac, dstMac, layers.EthernetTypeIPv4)
	ipv4 := getIPv4Layer(srcIp, dstIp, layers.IPProtocolTCP)
	tcp := getRstTcpLayer(srcPort, dstPort, seq)

	err = tcp.SetNetworkLayerForChecksum(&ipv4)
	if err != nil {
		return
	}

	serializeOptions := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, serializeOptions, &eth, &ipv4, &tcp)
	if err != nil {
		return
	}
	rstPacket := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return rstPacket, nil
}

func ForgeIPv6RstPacket(
	srcMac net.HardwareAddr,
	dstMac net.HardwareAddr,
	srcIp net.IP,
	dstIp net.IP,
	srcPort layers.TCPPort,
	dstPort layers.TCPPort,
	seq uint32,
) (packet gopacket.Packet, err error) {
	log.Debugf("Forging IPv6 RST Packet with seq \"%d\" from \"%s:%s\" to \"%s:%s\"",
		seq, srcIp.String(), srcPort.String(), dstIp.String(), dstPort.String())

	eth := getEthLayer(srcMac, dstMac, layers.EthernetTypeIPv6)
	ipv6 := getIPv6Layer(srcIp, dstIp, layers.IPProtocolTCP)
	tcp := getRstTcpLayer(srcPort, dstPort, seq)

	err = tcp.SetNetworkLayerForChecksum(&ipv6)
	if err != nil {
		return
	}

	serializeOptions := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, serializeOptions, &eth, &ipv6, &tcp)
	if err != nil {
		return
	}
	rstPacket := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeEthernet, gopacket.Default)
	return rstPacket, nil
}

func getEthLayer(srcMac net.HardwareAddr, dstMac net.HardwareAddr, ethernetType layers.EthernetType) layers.Ethernet {
	return layers.Ethernet{
		SrcMAC:       srcMac,
		DstMAC:       dstMac,
		EthernetType: ethernetType,
	}
}

func getRstTcpLayer(srcPort layers.TCPPort, dstPort layers.TCPPort, seq uint32) layers.TCP {
	return layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     seq,
		RST:     true,
	}

}

func getSynTCPLayer(srcPort layers.TCPPort, dstPort layers.TCPPort, seq uint32) layers.TCP {
	return layers.TCP{
		SrcPort: srcPort,
		DstPort: dstPort,
		Seq:     seq,
		SYN:     true,
	}
}

func getIPv4Layer(srcIp net.IP, dstIp net.IP, protocol layers.IPProtocol) layers.IPv4 {
	return layers.IPv4{
		SrcIP:    srcIp,
		DstIP:    dstIp,
		Version:  4,
		TTL:      64,
		Protocol: protocol,
	}
}

func getIPv6Layer(srcIp net.IP, dstIp net.IP, protocol layers.IPProtocol) layers.IPv6 {
	return layers.IPv6{
		SrcIP:      srcIp,
		DstIP:      dstIp,
		Version:    6,
		HopLimit:   64,
		NextHeader: protocol,
	}
}

func ForgeIPv4SynPackage(
	srcIp net.IP,
	dstIp net.IP,
	srcPort layers.TCPPort,
	dstPort layers.TCPPort,
	seq uint32,
) (packet gopacket.Packet, err error) {
	log.Debugf("Forging IPv4 SYN Packet with seq \"%d\" from \"%s:%s\" to \"%s:%s\"",
		seq, srcIp.String(), srcPort.String(), dstIp.String(), dstPort.String())

	ipv4 := getIPv4Layer(srcIp, dstIp, layers.IPProtocolTCP)
	tcp := getSynTCPLayer(srcPort, dstPort, seq)

	err = tcp.SetNetworkLayerForChecksum(&ipv4)
	if err != nil {
		return
	}

	serializeOptions := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	buffer := gopacket.NewSerializeBuffer()
	err = gopacket.SerializeLayers(buffer, serializeOptions, &ipv4, &tcp)
	if err != nil {
		return
	}

	synPacket := gopacket.NewPacket(buffer.Bytes(), layers.LayerTypeIPv4, gopacket.Default)
	return synPacket, nil
}
