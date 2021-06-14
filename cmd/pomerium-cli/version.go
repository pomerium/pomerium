package main

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/pomerium/pomerium/internal/version"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "version",
	Long:  `Print the cli version.`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("pomerium:", version.FullVersion())
	},
}
