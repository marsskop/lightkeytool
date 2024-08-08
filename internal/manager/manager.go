package manager

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"software.sslmate.com/src/go-pkcs12"
)

func Zeroing(buf []byte) {
	for i := range buf {
		buf[i] = 0
	}
}

func ReadKeyStore(filename string, password []byte, alias string, storeType string) (keystore.KeyStore, error) {
	switch storeType {
	case "JKS":
		return ReadKeyStoreJKS(filename, password)
	case "PKCS12":
		return ReadKeyStorePKCS12(filename, password, alias)
	default:
		return keystore.New(), nil
	}
}

func ReadKeyStoreJKS(filename string, password []byte) (ks keystore.KeyStore, err error) {
	ks = keystore.New()

	f, err := os.OpenFile(filename, os.O_RDONLY|os.O_CREATE, 0666)
	if err != nil {
		return ks, err
	}

	defer func() {
		err = f.Close()
	}()

	if err := ks.Load(f, password); err != nil {
		return ks, err
	}

	return ks, err
}

func ReadKeyStorePKCS12(filename string, password []byte, alias string) (ks keystore.KeyStore, err error) {
	ks = keystore.New()
	// empty alias means all entries; accepted PKCS12 keystore only has one entry
	if alias == "" {
		alias = "all"
	}
	f, err := os.OpenFile(filename, os.O_RDONLY|os.O_CREATE, 0666)
	if err != nil {
		return ks, err
	}
	defer func() {
		err = f.Close()
	}()
	p12, err := io.ReadAll(f)
	if err != nil {
		return ks, err
	}

	privkeyInterface, cert, cacerts, err := pkcs12.DecodeChain(p12, string(password))
	if err != nil {
		return ks, err
	}
	pk, ok := privkeyInterface.(crypto.PrivateKey)
	if !ok {
		return ks, fmt.Errorf("failed to get private key")
	}
	keybytes, err := x509.MarshalPKCS8PrivateKey(pk)
	if err != nil {
		return ks, err
	}
	certChain := []keystore.Certificate{
		{
			Type:    "X509",
			Content: cert.Raw,
		},
	}
	for _, c := range cacerts {
		certChain = append(certChain, keystore.Certificate{
			Type:    "X509",
			Content: c.Raw,
		})
	}
	pkeIn := keystore.PrivateKeyEntry{
		CreationTime: time.Now(),
		PrivateKey:   keybytes,
		CertificateChain: []keystore.Certificate{
			{
				Type:    "X509",
				Content: cert.Raw,
			},
		},
	}
	if err = ks.SetPrivateKeyEntry(alias, pkeIn, password); err != nil { // keypass is the same as storepass for PKCS12
		return ks, err
	}
	return ks, err
}

func WriteKeyStore(ks keystore.KeyStore, filename string, password []byte, storeType string) error {
	switch storeType {
	case "JKS":
		return WriteKeyStoreJKS(ks, filename, password)
	case "PKCS12":
		return WriteKeyStorePKCS12(ks, filename, password)
	default:
		return nil
	}
}

func WriteKeyStoreJKS(ks keystore.KeyStore, filename string, password []byte) (err error) {
	f, err := os.Create(filename)
	if err != nil {
		return err
	}

	defer func() {
		err = f.Close()
	}()

	err = ks.Store(f, password)
	if err != nil {
		return err
	}
	return err
}

func WriteKeyStorePKCS12(ks keystore.KeyStore, filename string, password []byte) (err error) {
	aliases := ks.Aliases()
	// should be only one alias for PKCS12
	if len(aliases) > 1 {
		return fmt.Errorf("PKCS12 keystore should not have more than one entry")
	}
	pke, err := ks.GetPrivateKeyEntry(aliases[0], password)
	if err != nil {
		return err
	}
	pkBytes := pke.PrivateKey
	var leafCert *x509.Certificate
	var certs []*x509.Certificate
	for i, c := range pke.CertificateChain {
		cert, err := x509.ParseCertificate(c.Content)
		if err != nil {
			return err
		}
		if i == 0 {
			leafCert = cert
		} else {
			certs = append(certs, cert)
		}
	}
	pk, err := x509.ParsePKCS8PrivateKey(pkBytes)
	if err != nil {
		return err
	}
	pfxData, err := pkcs12.LegacyDES.Encode(pk, leafCert, certs, string(password))
	if err != nil {
		return err
	}
	f, err := os.Create(filename) // truncates file if exists
	if err != nil {
		return err
	}
	defer func() {
		err = f.Close()
	}()
	if _, err = f.Write(pfxData); err != nil {
		return err
	}
	return err
}
