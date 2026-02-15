package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/spf13/cobra"

	"packeteer/internal/packet"
)

var (
	device string
	bpf    string
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "packeteer",
	Short: "packet sniffer",
	Long: `A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.`,
	Run: func(cmd *cobra.Command, args []string) {
		handleCmd(cmd)
	},
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is $HOME/.packeteer.yaml)")

	// rootCmd.Flags().BoolP("toggle", "t", false, "Help message for toggle")
	rootCmd.Flags().BoolP("find-interfaces", "i", false, "")
	rootCmd.Flags().
		StringVarP(&device, "device", "d", "", "set device to listen to (ex. wlan0, eth0)")
	rootCmd.Flags().StringVarP(&bpf, "bpf", "b", "", "set bpf filters")
}

func handleCmd(cmd *cobra.Command) {
	search, err := cmd.Flags().GetBool("find-interfaces")
	if err != nil {
		log.Fatal(err)
	}

	if search || device == "" {
		device, err = packet.SelectInterface(pcap.FindAllDevs)
		if err != nil {
			log.Fatal(err)
		}
	}

	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	if bpf != "" {
		if err := handle.SetBPFFilter(bpf); err != nil {
			log.Fatal(err)
		}
	}

	n := 0
	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	for p := range packetSrc.Packets() {
		pi := packet.ExtractPacketInfo(p)
		if pi == nil {
			log.Fatal("PacketInfo is nil")
		}

		fmt.Printf("PACKET: %d | ", n)
		packet.PrintPacketInfo(pi)
		n++
	}
}
