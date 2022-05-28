package internal

import (
	"errors"
	"fmt"

	"github.com/google/gopacket/pcap"
)

func GetSystemInterfaces() []pcap.Interface {
	interfaces, err := pcap.FindAllDevs()
	if err != nil {
		return []pcap.Interface{}
	}
	return interfaces
}

func GetPcapInterfaceForName(name string) (interf *pcap.Interface, err error) {
	for _, item := range GetSystemInterfaces() {
		if item.Name == name {
			return &item, nil
		}
	}
	return &pcap.Interface{}, errors.New(fmt.Sprintf("interface with name %s not found", name))
}

func FindSystemInterfaceForIP(ip string) (interf *pcap.Interface, err error) {
	for _, item := range GetSystemInterfaces() {
		for _, address := range item.Addresses {
			if address.IP.String() == ip {
				return &item, nil
			}
		}
	}
	return &pcap.Interface{}, errors.New(fmt.Sprintf("no interface found for address %s", ip))
}
