package cmd

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"packeteer/internal/storage"
)

var db *sql.DB

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "packeteer",
	Short: "packet sniffer",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Set up DB
		var err error
		db, err = storage.OpenDb(viper.GetString("db_path"))
		if err != nil {
			log.Fatalf("error opening db: %v", err)
		}
	},
	PersistentPostRun: func(cmd *cobra.Command, args []string) {
		db.Close()
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
