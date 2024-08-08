package cmd

import (
	"fmt"

	"github.com/marsskop/lightkeytool/internal/manager"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

var (
	srckeystore       string
	destkeystore      string
	srcstoretype      string
	deststoretype     string
	srcstorepass      string
	deststorepass     string
	srcalias          string
	destalias         string
	srckeypass        string
	destkeypass       string
	importkeystoreCmd = &cobra.Command{
		Use:   "importkeystore",
		Short: "Import contents from another keystore",
		Long: `Imports a single entry or all entries from a source keystore to a destination keystore.

		When the -srcalias option is provided, the command imports the single entry identified by the alias to the destination keystore. If a destination alias is not provided with destalias, then srcalias is used as the destination alias. If the source entry is protected by a password, then srckeypass is used to recover the entry. If srckeypass is not provided, then the keytool command attempts to use srcstorepass to recover the entry. If srcstorepass is either not provided or is incorrect, then the user is prompted for a password. The destination entry is protected with destkeypass. If destkeypass is not provided, then the destination entry is protected with the source entry password. For example, most third-party tools require storepass and keypass in a PKCS #12 keystore to be the same. In order to create a PKCS #12 keystore for these tools, always specify a -destkeypass to be the same as -deststorepass.
		
		If the -srcalias option is not provided, then all entries in the source keystore are imported into the destination keystore. Each destination entry is stored under the alias from the source entry. If the source entry is protected by a password, then srcstorepass is used to recover the entry. If srcstorepass is either not provided or is incorrect, then the user is prompted for a password. If a source keystore entry type is not supported in the destination keystore, or if an error occurs while storing an entry into the destination keystore, then the user is prompted whether to skip the entry and continue or to quit. The destination entry is protected with the source entry password.
		
		If the destination alias already exists in the destination keystore, then the user is prompted to either overwrite the entry or to create a new entry under a different alias name.
		
		If the -noprompt option is provided, then the user is not prompted for a new destination alias. Existing entries are overwritten with the destination alias name. Entries that cannot be imported are skipped and a warning is displayed.`,
		RunE: importKeystore,
	}
)

func init() {
	RootCmd.AddCommand(importkeystoreCmd)
	importkeystoreCmd.Flags().StringVar(&srckeystore, "srckeystore", "", "source keystore to import from")
	importkeystoreCmd.Flags().StringVar(&destkeystore, "destkeystore", "", "destination keystore to import into")
	importkeystoreCmd.Flags().StringVar(&srcstoretype, "srcstoretype", "JKS", "source keystore type")
	importkeystoreCmd.Flags().StringVar(&deststoretype, "deststoretype", "JKS", "destination keystore type")
	importkeystoreCmd.Flags().StringVar(&srcstorepass, "srcstorepass", "", "source keystore password")
	importkeystoreCmd.Flags().StringVar(&deststorepass, "deststorepass", "", "destination keystore password")
	importkeystoreCmd.Flags().StringVar(&srcalias, "srcalias", "", "source entry alias")
	importkeystoreCmd.Flags().StringVar(&destalias, "destalias", "", "destination entry alias")
	importkeystoreCmd.Flags().StringVar(&srckeypass, "srckeypass", "", "source key password")
	importkeystoreCmd.Flags().StringVar(&destkeypass, "destkeypass", "", "destination key password")
	importkeystoreCmd.MarkFlagRequired("srckeystore")
	importkeystoreCmd.MarkFlagRequired("destkeystore")
	importkeystoreCmd.MarkFlagRequired("srcstorepass")
	importkeystoreCmd.MarkFlagRequired("deststorepass")
}

func importKeystore(cmd *cobra.Command, args []string) error {
	// analog: keytool -importkeystore -srckeystore <srclkeystore> -destkeystore <destkeystore> [-srcstoretype JKS|PKCS12] [-deststoretype JKS|PKCS12] [-srcstorepass <srcstorepass>] [-deststorepass <deststorepass>] [-srckeypass <srckeypass>] [-destkeypass <destkeypass>] [-srcalias <srcalias>] [-destalias <destalias>] -noprompt
	// validate flags
	if srcstoretype != "JKS" && srcstoretype != "PKCS12" {
		return fmt.Errorf("wrong srcstoretype; should be JKS or PKCS12")
	}
	if deststoretype != "JKS" && deststoretype != "PKCS12" {
		return fmt.Errorf("wrong deststoretype; should be JKS or PKCS12")
	}
	// if srcalias == "", import all certificates
	if destalias == "" && srcalias != "" {
		destalias = srcalias
	}
	if srckeypass == "" {
		srckeypass = srcstorepass
	}
	if destkeypass == "" {
		destkeypass = srckeypass
	}
	if srcstorepass == "PKCS12" && srcstorepass != srckeypass {
		srckeypass = srcstorepass
		log.Warn("Different store and key passwords not supported for PKCS12 KeyStores. Ignoring user-specified --srckeypass value.")
	}
	if deststoretype == "PKCS12" && deststorepass != destkeypass {
		destkeypass = deststorepass
		log.Warn("Different store and key passwords not supported for PKCS12 KeyStores. Ignoring user-specified --destkeypass value.")
	}
	bSrcStorePass := []byte(srcstorepass)
	defer manager.Zeroing(bSrcStorePass)
	bSrcKeyPass := []byte(srckeypass)
	defer manager.Zeroing(bSrcKeyPass)
	bDestStorePass := []byte(deststorepass)
	defer manager.Zeroing(bDestStorePass)
	bDestKeyPass := []byte(destkeypass)
	defer manager.Zeroing(bDestKeyPass)

	// process source keystore
	srcKs, err := manager.ReadKeyStore(srckeystore, bSrcStorePass, srcalias, srcstoretype)
	if err != nil {
		return err
	}
	// process destination keystore
	destKs, err := manager.ReadKeyStore(destkeystore, bDestStorePass, destalias, deststoretype)
	if err != nil {
		return err
	}
	// import srcalias entry as destalias, or all entries if srcalias is empty
	if srcalias != "" {
		pke, err := srcKs.GetPrivateKeyEntry(srcalias, bSrcKeyPass)
		if err != nil {
			return err
		}
		if err = destKs.SetPrivateKeyEntry(destalias, pke, bDestKeyPass); err != nil {
			return err
		}
	} else {
		for _, alias := range srcKs.Aliases() {
			pke, err := srcKs.GetPrivateKeyEntry(alias, bSrcKeyPass)
			if err != nil {
				return err
			}
			if err = destKs.SetPrivateKeyEntry(alias, pke, bDestKeyPass); err != nil {
				return err
			}
		}
	}
	// write destination keystore
	err = manager.WriteKeyStore(destKs, destkeystore, bDestStorePass, deststoretype)
	if err != nil {
		return err
	}
	return nil
}
