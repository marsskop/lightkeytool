package cmd

import (
	"bytes"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/marsskop/lightkeytool/internal/manager"
	log "github.com/sirupsen/logrus"

	"github.com/spf13/cobra"
)

var (
	importcertCmd = &cobra.Command{
		Use:   "importcert",
		Short: "Import a certificate/certificate chain to a keystore",
		Long: `Reads the certificate or certificate chain (where the latter is supplied in a PKCS#7 formatted reply or a sequence of X.509 certificates) from the file cert_file, and stores it in the keystore entry identified by alias. If no file is specified, then the certificate or certificate chain is read from stdin.

The lightkeytool command can import X.509 v1, v2, and v3 certificates, and PKCS#7 formatted certificate chains consisting of certificates of that type. The data to be imported must be provided either in binary encoding format or in printable encoding format (also known as Base64 encoding) as defined by the Internet RFC 1421 standard. In the latter case, the encoding must be bounded at the beginning by a string that starts with -----BEGIN, and bounded at the end by a string that starts with -----END.

You import a certificate for two reasons: To add it to the list of trusted certificates, and to import a certificate reply received from a certificate authority (CA) as the result of submitting a Certificate Signing Request to that CA.

Which type of import is intended is indicated by the value of the -alias option. If the alias does not point to a key entry, then the light command assumes you are adding a trusted certificate entry. In this case, the alias should not already exist in the keystore. If the alias does already exist, then the light command outputs an error because there is already a trusted certificate for that alias, and does not import the certificate. If the alias points to a key entry, then the light command assumes you are importing a certificate reply.`,
		RunE: importCert,
	}
)

func init() {
	RootCmd.AddCommand(importcertCmd)
	importcertCmd.Flags().StringVar(&keystore, "keystore", "", "keystore to import ino")
	importcertCmd.Flags().StringVar(&alias, "alias", "mykey", "alias name of the entry to process")
	importcertCmd.Flags().StringVar(&storetype, "storetype", "JKS", "keystore type: jks or p12")
	importcertCmd.Flags().StringVar(&storepass, "storepass", "", "keystore password")
	importcertCmd.Flags().StringVar(&keypass, "keypass", "", "key password, if importing certificate reply")
	importcertCmd.Flags().StringVar(&file, "file", "", "input file name")
	err := importcertCmd.MarkFlagRequired("keystore")
	if err != nil {
		log.Fatal(err)
	}
	err = importcertCmd.MarkFlagRequired("storepass")
	if err != nil {
		log.Fatal(err)
	}
	err = importcertCmd.MarkFlagRequired("alias")
	if err != nil {
		log.Fatal(err)
	}
}

func importCert(cmd *cobra.Command, args []string) error {
	// analog: keytool -importcert -keystore <keystore> -alias <alias> [-storetype JKS|PKCS12] [-storepass <storepass>] [-keypass <keypass>] [-file <file>]
	// validate flags
	if storetype != "JKS" && storetype != "PKCS12" {
		return fmt.Errorf("wrong storetype; should be JKS or PKCS12")
	}
	bStorePass := []byte(storepass)
	defer manager.Zeroing(bStorePass)

	// read from stdin (if file flag is undefined) or file
	var err error
	fi := os.Stdin
	if file == "" {
		stat, _ := fi.Stat()
		if (stat.Mode() & os.ModeCharDevice) != 0 {
			return fmt.Errorf("no data in stdin")
		}
	} else {
		fi, err = os.Open(file)
		if err != nil {
			return err
		}
		defer fi.Close()
	}
	data, err := io.ReadAll(fi)
	if err != nil {
		return err
	}
	blockBytes := data
	// if starts with -----BEGIN, it is PEM and should be decoded
	if bytes.HasPrefix(data, []byte("-----BEGIN")) {
		block, _ := pem.Decode(data)
		if block == nil {
			return fmt.Errorf("failed to decode PEM block")
		}
		blockBytes = block.Bytes
	}

	// process keystore
	ks, err := manager.ReadKeyStore(keystore, bStorePass, storetype)
	if err != nil {
		return err
	}
	// type of import is indicated by the alias
	// if the alias points to an existing trusted certificate entry, it returns a error
	if ks.IsTrustedCertificateEntry(alias) {
		return fmt.Errorf("trusted certificate entry by alias %s exists", alias)
	}
	// if the alias points to a private key entry, it assumes it is importing a certificate reply
	if ks.IsPrivateKeyEntry(alias) {
		bKeyPass := []byte(keypass)
		defer manager.Zeroing(bKeyPass)
		pke, err := ks.GetPrivateKeyEntry(alias, bKeyPass)
		if err != nil {
			return err
		}
		pke.CertificateChain = append(pke.CertificateChain, manager.CreateCertificate(blockBytes))
		err = ks.SetPrivateKeyEntry(alias, pke, bKeyPass)
		if err != nil {
			return err
		}
	} else {
		// if the alias doesn't point to any entry, it assumes it creates a trusted certificate entry by that alias (which cannot be PKC7)
		entry := manager.CreateTrustedCertificateEntry(time.Now(), blockBytes)
		err = ks.SetTrustedCertificateEntry(alias, entry)
		if err != nil {
			return err
		}
	}
	// write updated keystore
	err = manager.WriteKeyStore(ks, keystore, bStorePass, storetype)
	if err != nil {
		return err
	}
	return nil
}
