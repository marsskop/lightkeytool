package display

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/pem"
	"fmt"
	"hash"
	"os"
	"text/template"
	"time"

	"github.com/marsskop/keystore-go"
)

const (
	providerNameDefault = "SUN" // default
	displayTmpl         = `Keystore type: {{ .StoreType }}
Keystore provider: {{ .ProviderName }}

Your keystore contains {{ .NumEntries }} {{if eq .NumEntries 1}}entry{{else}}entries{{end}}
{{ range $ind, $entry := .Entries }}
{{ $entry.Alias }}, {{ $entry.CreationTime.Format "Jan 2, 2006" | print }}, {{ $entry.EntryType }},
Certificate fingerprint (SHA-256): {{ $entry.FingerprintSHA256 }}
{{- end }}`

// displayTmplRFC     = ""
)

type KeystoreRepr struct {
	StoreType    string
	ProviderName string
	NumEntries   int
	Entries      map[string]entryRepr // map alias -> entry
}

type entryRepr struct {
	Alias             string
	CreationTime      time.Time
	EntryType         string
	FingerprintSHA1   string
	FingerprintSHA256 string
	RFC               []byte
}

func RFC(content []byte) []byte {
	block := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: content,
	}
	return pem.EncodeToMemory(block)
}

func fingerprint(algorithm string, content []byte) string {
	var h hash.Hash
	if algorithm == "SHA1" {
		h = sha1.New()
	} else if algorithm == "SHA256" {
		h = sha256.New()
	} else {
		return ""
	}
	h.Write(content)
	fingerprint := h.Sum(nil)
	var buf bytes.Buffer
	for i, f := range fingerprint {
		if i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02X", f)
	}
	return buf.String()
}

func NewKeystoreRepr(ks keystore.KeyStore, bstorepass []byte, StoreType string, providerName string) (ksr KeystoreRepr, err error) {
	ksr.StoreType = StoreType
	ksr.ProviderName = providerNameDefault
	if providerName != "" {
		ksr.ProviderName = providerName
	}
	aliases := ks.Aliases()
	numEntries := len(aliases)
	ksr.NumEntries = numEntries
	ksr.Entries = make(map[string]entryRepr)
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
		fingerprintSHA1 := fingerprint("SHA1", content)
		fingerprintSHA256 := fingerprint("SHA256", content)
		e := entryRepr{
			Alias:             alias,
			EntryType:         entryType,
			CreationTime:      creationTime,
			FingerprintSHA1:   fingerprintSHA1,
			FingerprintSHA256: fingerprintSHA256,
			RFC:               RFC(content),
		}
		ksr.Entries[alias] = e
	}
	return ksr, err
}

func DisplayKeystore(ks keystore.KeyStore, bstorepass []byte, alias string, StoreType string) error {
	ksr, err := NewKeystoreRepr(ks, bstorepass, StoreType, providerNameDefault)
	if err != nil {
		return err
	}
	t, err := template.New("displayTmpl").Parse(displayTmpl)
	if err != nil {
		return err
	}
	t.Execute(os.Stdout, ksr)
	return nil
}
