package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var (
	// version will be filled at compile time.
	version = "N/A"
	Verbose bool
	RootCmd = &cobra.Command{
		Use:     "lightkeytool",
		Version: version,
		Short:   "LightKeytool is a no-Java version of keytool",
		Long:    "A lightweight CLI implementation of keytool that requires no Java JDK to be installed.",
	}
)

func Execute() {
	if err := RootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	RootCmd.PersistentFlags().BoolVarP(&Verbose, "verbose", "v", false, "verbose output") // TODO: enable verbose output
}
