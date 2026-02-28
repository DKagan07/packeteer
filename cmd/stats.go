package cmd

import (
	"log"

	"github.com/spf13/cobra"

	"packeteer/internal/output"
	"packeteer/internal/storage"
)

// dnsStatsCmd represents the stats command
var dnsStatsCmd = &cobra.Command{
	Use:   "dns-stats",
	Short: "get some dns stats",
	Run: func(cmd *cobra.Command, args []string) {
		GetStats(cmd, args)
	},
}

func init() {
	rootCmd.AddCommand(dnsStatsCmd)

	dnsStatsCmd.Flags().
		BoolP("most-queried", "m", false, "most queried domains") // most queried domains
	dnsStatsCmd.Flags().BoolP("over-time", "t", false, "queries over time") // queries over time
	dnsStatsCmd.Flags().
		BoolP("unique", "u", false, "unique domians per source IP") // unique domains per src IP
}

// GetStats will pretty-print stats depending on the flag used
func GetStats(cmd *cobra.Command, args []string) {
	if mqf, _ := cmd.Flags().GetBool("most-queried"); mqf {
		domains, err := storage.GetMostQueriedDomains(db)
		if err != nil {
			log.Fatal(err)
		}

		// need to pretty print this list
		output.PrintMostQueriedDomains(domains)
	}

	if otf, _ := cmd.Flags().GetBool("over-time"); otf {
		storage.GetQueriesOverTime(db)
	}

	if uf, _ := cmd.Flags().GetBool("unique"); uf {
		storage.GetUniqueDomains(db)
	}

	// _, err := storage.GetDNSEntries(db)
	// if err != nil {
	// 	log.Fatal(err)
	// }
	//
	// for _, e := range dnsEntries {
	// 	fmt.Println("cname paths: ", e.CNamePath)
	// 	fmt.Println("reponse IPs: ", e.ResponseIPs)
	// 	fmt.Println()
	// }
}
