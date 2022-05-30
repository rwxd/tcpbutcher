package cmd

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/rwxd/tcpbutcher/internal"
	"github.com/rwxd/tcpbutcher/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "tcpbutcher",
	Short: "TCP connection butcher, bpf can be passed as args or via cli options.",
	Long: `TCP connection butcher, bpf can be passed as args or via cli options.

Examples:
BPF syntax
sudo tcpbutcher -i eno1 host host.domain.com and src port 22
sudo tcpbutcher -i eno1 host 2a02:8188:1640:1af0:dea6:32ff:fe50:5b1a and src port 22

Cli options
sudo tcpbutcher -i eno1 --host host.domain.com --src-port 22
sudo tcpbutcher -i eno1 --host 2a02:8188:1640:1af0:dea6:32ff:fe50:5b1a --src-port 22

More information on https://github.com/rwxd/tcpbutcher
    `,
	Run: func(cmd *cobra.Command, args []string) {
		dstPort, _ := cmd.Flags().GetInt("dst-port")
		srcPort, _ := cmd.Flags().GetInt("src-port")
		host, _ := cmd.Flags().GetString("host")
		srcHost, _ := cmd.Flags().GetString("src")
		dstHost, _ := cmd.Flags().GetString("dst")
		interf, _ := cmd.Flags().GetString("interface")
		argsBpfFilter := strings.Join(args[:], " ")

		logLevel, err := utils.GetLogrusLogLevelFromString(cmd.Flag("log-level").Value.String())
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		log.SetLevel(logLevel)

		if !utils.IsRoot() {
			fmt.Println("Tool not started as root user, permissions may be missing")
		}

		var pcapInterface *pcap.Interface

		if len(interf) > 0 {
			pcapInterface, err = internal.GetPcapInterfaceForName(interf)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			log.Infof("System Interface %s found\n", pcapInterface.Name)
		} else if len(interf) == 0 && len(host) > 0 {
			pcapInterface, err = internal.FindSystemInterfaceForIP(srcHost)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			log.Infof("System Interface %s found for ip %s\n", pcapInterface.Name, host)
		} else if len(interf) == 0 && len(srcHost) > 0 {
			pcapInterface, err = internal.FindSystemInterfaceForIP(srcHost)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			log.Infof("System Interface %s found for ip %s\n", pcapInterface.Name, srcHost)
		} else if len(interf) == 0 && len(dstHost) > 0 {
			pcapInterface, err = internal.FindSystemInterfaceForIP(dstHost)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			log.Infof("System Interface %s found for ip %s\n", pcapInterface.Name, dstHost)
		}

		if len(pcapInterface.Name) == 0 {
			fmt.Println("Could not find an interface trough cli options, use \"-i <name>\"")
		}

		log.Infof("BPF Filter trough args: \"%s\"\n", argsBpfFilter)

		cliBpfFilter := internal.GetBpfFilter(host, srcHost, dstHost, srcPort, dstPort)

		log.Infof("BPF Filter trough options: \"%s\"\n", argsBpfFilter)

		combinedBpfFilter := internal.CombineBpfFilters(argsBpfFilter, cliBpfFilter)
		log.Infof("Created combined bpf filter from options and args with value \"%s\"", combinedBpfFilter)

		fmt.Printf("Creating listener on interface %s\n", pcapInterface.Name)
		handle, err := internal.GetPcapHandleWithFilter(pcapInterface, argsBpfFilter)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}
		log.Debug("Created pcap handle")

		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

		fmt.Println("Listening for packets, cancel with Ctrl-c...")
		internal.ButcherConnections(packetSource, handle)
	},
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.Flags().IntP("dst-port", "p", 0, "destination port")
	rootCmd.Flags().Int("src-port", 0, "source port")
	rootCmd.Flags().String("host", "", "host")
	rootCmd.Flags().StringP("src", "s", "", "source host")
	rootCmd.Flags().StringP("dst", "d", "", "destination host")
	rootCmd.Flags().StringP("interface", "i", "", "interface")
	rootCmd.Flags().Bool("server", false, "cancel connections to this device")
	rootCmd.Flags().String("log-level", "error", "log level")
}
