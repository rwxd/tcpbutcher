package internal

import (
	"errors"
	"fmt"

	"github.com/google/gopacket/pcap"
	log "github.com/sirupsen/logrus"
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

func CheckIpLocal(ip string) bool {
	interf, err := FindSystemInterfaceForIP(ip)
	if err != nil {
		return false
	}
	log.Debugf("Found ip %s on interface %s", ip, interf.Name)
	return true
}
