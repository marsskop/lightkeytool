package cmd

import (
	"encoding/pem"
	"fmt"
	"os"

	log "github.com/sirupsen/logrus"

	"github.com/marsskop/lightkeytool/internal/manager"
	"github.com/spf13/cobra"
)

var (
	keystore      string
	storetype     string
	alias         string
	storepass     string
	rfc           bool
	file          string
	exportcertCmd = &cobra.Command{
		Use:   "exportcert",
		Short: "Export data",
		Long: `Reads from the keystore the certificate associated with alias and stores it in the cert_file file. When no file is specified, the certificate is output to stdout.

		The certificate is by default output in binary encoding. If the -rfc option is specified, then the output in the printable encoding format defined by the Internet RFC 1421 Certificate Encoding Standard.
		
		If alias refers to a trusted certificate, then that certificate is output. Otherwise, alias refers to a key entry with an associated certificate chain. In that case, the first certificate in the chain is returned. This certificate authenticates the public key of the entity addressed by alias.`,
		RunE: exportCert,
	}
)

func init() {
	RootCmd.AddCommand(exportcertCmd)
	exportcertCmd.Flags().StringVar(&keystore, "keystore", "", "keystore to read from")
	exportcertCmd.Flags().StringVar(&storetype, "storetype", "JKS", "keystore type: jks or p12")
	exportcertCmd.Flags().StringVar(&alias, "alias", "mykey", "alias name of the entry to process")
	exportcertCmd.Flags().StringVar(&storepass, "storepass", "", "keystore password")
	exportcertCmd.Flags().BoolVar(&rfc, "rfc", false, "output in RFC style")
	exportcertCmd.Flags().StringVar(&file, "file", "", "output file name")
	err := exportcertCmd.MarkFlagRequired("keystore")
	if err != nil {
		log.Fatal(err)
	}
	err = exportcertCmd.MarkFlagRequired("storepass")
	if err != nil {
		log.Fatal(err)
	}
}

func exportCert(cmd *cobra.Command, args []string) error {
	// analog: keytool -exportcert -keystore <keystore> [-rfc] [-storetype JKS|PKCS12] [-alias <alias>] [-storepass <storepass>] [-file <file>]
	// validate flags
	if storetype != "JKS" && storetype != "PKCS12" {
		return fmt.Errorf("wrong storetype; should be JKS or PKCS12")
	}
	bStorePass := []byte(storepass)
	defer manager.Zeroing(bStorePass)

	// process keystore
	ks, err := manager.ReadKeyStore(keystore, bStorePass, alias, storetype)
	if err != nil {
		return err
	}
	certChain, err := ks.GetPrivateKeyEntryCertificateChain(alias)
	if err != nil {
		return err
	}
	fo := os.Stdout
	if file != "" {
		fo, err = os.Create(file)
		if err != nil {
			return err
		}
		defer fo.Close()
	}
	if rfc {
		// convert to RFC format
		block := &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: certChain[0].Content,
		}

		if err := pem.Encode(fo, block); err != nil {
			return err
		}
	} else {
		if _, err := fo.Write(certChain[0].Content); err != nil {
			return err
		}
	}
	return nil
}
