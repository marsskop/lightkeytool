package cmd

import (
	"fmt"

	"github.com/marsskop/lightkeytool/internal/display"
	"github.com/marsskop/lightkeytool/internal/manager"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	listCmd = &cobra.Command{
		Use:   "list",
		Short: "List contents of the keystore",
		Long: `Prints to stdout the contents of the keystore entry identified by alias. If no alias is specified, then the contents of the entire keystore are printed.

This command by default prints the SHA256 fingerprint of a certificate. If the -v option is specified, then the certificate is printed in human-readable format, with additional information such as the owner, issuer, serial number, and any extensions. If the --rfc option is specified, then the certificate contents are printed using the printable encoding format, as defined by the Internet RFC 1421 Certificate Encoding Standard.
		
You cannot specify both -v and --rfc.`,
		RunE: list,
	}
)

func init() {
	RootCmd.AddCommand(listCmd)
	listCmd.Flags().StringVar(&keystore, "keystore", "", "keystore to read from")
	listCmd.Flags().StringVar(&storetype, "storetype", "JKS", "keystore type: jks or p12")
	listCmd.Flags().StringVar(&alias, "alias", "mykey", "alias name of the entry to process")
	listCmd.Flags().StringVar(&storepass, "storepass", "", "keystore password")
	//listCmd.Flags().BoolVar(&rfc, "rfc", false, "output in RFC style")  // TODO: enable RFC output
	err := listCmd.MarkFlagRequired("keystore")
	if err != nil {
		log.Fatal(err)
	}
	err = listCmd.MarkFlagRequired("storepass")
	if err != nil {
		log.Fatal(err)
	}
}

func list(cmd *cobra.Command, args []string) error {
	// analog: keytool -list -keystore <keystore> -storepass <storepass> [-storetype JKS|PKCS12] [-alias <alias>] [-rfc]
	// validate flags
	if storetype != "JKS" && storetype != "PKCS12" {
		return fmt.Errorf("wrong storetype; should be JKS or PKCS12")
	}
	bStorePass := []byte(storepass)
	defer manager.Zeroing(bStorePass)

	// process keystore
	ks, err := manager.ReadKeyStore(keystore, bStorePass, storetype) // alias is required only for PKCS12
	if err != nil {
		return err
	}
	err = display.DisplayKeystore(ks, bStorePass, alias, storetype)
	if err != nil {
		return err
	}

	return nil
}
