package cmd

import (
	"fmt"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/rwxd/tcpbutcher/internal"
	"github.com/rwxd/tcpbutcher/utils"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "tcpbutcher",
	Short: "TCP connection butcher",
	Run: func(cmd *cobra.Command, args []string) {
		dstPort, _ := cmd.Flags().GetInt("dst-port")
		srcPort, _ := cmd.Flags().GetInt("src-port")
		srcHost, _ := cmd.Flags().GetString("src")
		dstHost, _ := cmd.Flags().GetString("dst")
		interf, _ := cmd.Flags().GetString("interface")
		logLevel, err := utils.GetLogrusLogLevelFromString(cmd.Flag("log-level").Value.String())
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
			fmt.Printf("System Interface %s found\n", pcapInterface.Name)
		} else if len(interf) == 0 && len(srcHost) > 0 {
			pcapInterface, err = internal.FindSystemInterfaceForIP(srcHost)
			if err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
			log.Infof("System Interface %s found for ip %s\n", pcapInterface.Name, srcHost)
		}

		pcapFilters := internal.GetBpfFilter(srcHost, dstHost, srcPort, dstPort)
		log.Infof("Created bpf filter from cli options with value \"%s\"", pcapFilters)

		handle, err := internal.GetPcapHandleWithFilter(pcapInterface, pcapFilters)
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
	rootCmd.Flags().StringP("src", "s", "", "source host")
	rootCmd.Flags().StringP("dst", "d", "", "destination host")
	rootCmd.Flags().StringP("interface", "i", "", "interface")
	rootCmd.Flags().String("log-level", "error", "log level")
}
