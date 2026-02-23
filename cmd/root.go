package cmd

import (
	"fmt"
	"log"
	"os"
	"path"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/pcap"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"packeteer/internal/dns"
	"packeteer/internal/packet"
	"packeteer/internal/storage"
)

var (
	device  string
	bpf     string
	cfgFile string

	homeDir, _ = os.UserHomeDir()
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
	cobra.OnInitialize(initConfig)

	rootCmd.PersistentFlags().
		StringVar(&cfgFile, "config", path.Join(homeDir, ".packeteer.yaml"), "config file")

	rootCmd.Flags().BoolP("find-interfaces", "i", false, "")
	rootCmd.Flags().
		StringVarP(&device, "device", "d", "", "set device to listen to (ex. wlan0, eth0)")
	rootCmd.Flags().StringVarP(&bpf, "bpf", "b", "", "set bpf filters")
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		fmt.Println("no config file set")
		panic(
			"no config file set. Please create a $HOME/.packeteer.yaml file or pass in a new path",
		)
	}

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			log.Fatal(err)
		}
	}
}

func handleCmd(cmd *cobra.Command) {
	// Set up DB
	db, err := storage.OpenDb(viper.GetString("db_path"))
	if err != nil {
		log.Fatalf("error opening db: %v", err)
	}
	defer db.Close()

	// Get interface to sniff
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

	// Open connection
	handle, err := pcap.OpenLive(device, 1600, true, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}

	if bpf != "" {
		if err := handle.SetBPFFilter(bpf); err != nil {
			log.Fatal(err)
		}
	}

	// Packet processing
	n := 0
	packetSrc := gopacket.NewPacketSource(handle, handle.LinkType())
	for p := range packetSrc.Packets() {
		pi, dnsInfo := packet.ExtractPacketInfo(p)
		if pi == nil {
			log.Fatal("PacketInfo is nil")
		}

		if dnsInfo != nil {
			if err := dns.InsertDNSInfo(dnsInfo, db); err != nil {
				log.Fatalf("inserting into dns table: %v", err)
			}
		}

		packet.PrintPacketInfo(pi, n)
		n++
	}
}
