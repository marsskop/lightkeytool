package display

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"time"

	"github.com/marsskop/keystore-go"
)

const (
	providerNameDefault = "SUN" // default
// 	displayTmpl         = `Keystore type: {{ .Storetype }}
// Keystore provider: {{ .ProviderName }}

// Your keystore contains {{ .NumEntries }} entries
// {{ range .Entries }}
// {{ .Alias }}, {{ .Entry.CreationTime }}, {{ .EntryType }},
// Certificate fingerprint (SHA-256): {{ .Fingerprint }}
// {{- end }}`
//
//	displayTmplRFC     = ""
//	displayTmplVerbose = ""
)

type KeystoreRepr struct {
	Storetype    string
	ProviderName string
	NumEntries   int
	Entries      map[string]entryRepr // map alias -> entry
}

type entryRepr struct {
	Alias            string
	CreationTime     time.Time
	EntryType        string
	FingerprintSHA1  string
	FingerpintSHA256 string
	RFC              []byte
}

func RFC(content []byte) []byte {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: content,
	}
	return pem.EncodeToMemory(block)
}

func NewKeystoreRepr(ks keystore.KeyStore, bstorepass []byte, storetype string, providerName string) (ksr KeystoreRepr, err error) {
	ksr.Storetype = storetype
	ksr.ProviderName = providerNameDefault
	if providerName != "" {
		ksr.ProviderName = providerName
	}
	aliases := ks.Aliases()
	numEntries := len(aliases)
	ksr.NumEntries = numEntries
	for _, alias := range aliases {
		var entryType string
		var entry interface{}
		var content []byte
		var creationTime time.Time
		if ks.IsPrivateKeyEntry(alias) {
			entryType = "PrivateKeyEntry"
			certChain, err := ks.GetPrivateKeyEntryCertificateChain(alias)
			if err != nil {
				return ksr, err
			}
			content = certChain[0].Content
			creationTime, err = ks.GetCreationTime(alias)
			if err != nil {
				return ksr, err
			}
		} else if ks.IsTrustedCertificateEntry(alias) {
			entryType = "TrustedCertificateEntry"
			entry, err = ks.GetTrustedCertificateEntry(alias)
			if err != nil {
				return ksr, err
			}
			trust, _ := entry.(keystore.TrustedCertificateEntry)
			content = trust.Certificate.Content
			creationTime, err = ks.GetCreationTime(alias)
			if err != nil {
				return ksr, err
			}
		} else {
			return ksr, fmt.Errorf("unrecognized entry type")
		}
		h1 := sha1.New()
		h1.Write(content)
		sha1Hash := hex.EncodeToString(h1.Sum(nil))
		h256 := sha256.New()
		h256.Write(content)
		sha256Hash := hex.EncodeToString(h1.Sum(nil))
		e := entryRepr{
			Alias:            alias,
			EntryType:        entryType,
			CreationTime:     creationTime,
			FingerprintSHA1:  sha1Hash,
			FingerpintSHA256: sha256Hash,
			RFC:              RFC(content),
		}
		fmt.Println(e)
	}
	fmt.Println(ksr)
	return ksr, err
}

// func DisplayKeystore(ks keystore.KeyStore, storetype string, rfc bool, alias string) (string, error) {
// 	ksr, err := NewKeystoreRepr(ks, bstorepass, storetype, providerNameDefault)
// 	return "", nil
// }
