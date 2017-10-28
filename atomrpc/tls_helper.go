package atomrpc

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"time"
)

// NOTE:TLS USED THIS WAY IS INSECURE. ONLY TO MEASURE PERFORMANCE
func AtomTLSConfig() (*tls.Certificate, *tls.Config) {
	_, certB, keyB, err := GenCert()
	if err != nil {
		log.Fatal("Couldn't generate TLS cert", err)
	}
	cert, err := tls.X509KeyPair(certB, keyB)
	if err != nil {
		log.Fatal("Couldn't load TLS cert:", err)
	}
	var config tls.Config
	config.InsecureSkipVerify = true
	config.Certificates = []tls.Certificate{cert}
	config.ClientAuth = tls.NoClientCert
	return &cert, &config
}

func GenCert() (*x509.Certificate, []byte, []byte, error) {
	// generate a random serial number (a real cert authority would have some logic behind this)
	tmpl := &x509.Certificate{
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		PublicKeyAlgorithm: x509.ECDSA,
		Version:            2, // x509v3
		SerialNumber:       new(big.Int).SetInt64(1),
		Subject:            pkix.Name{Organization: []string{"Atom"}},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().AddDate(1 /* years */, 0 /* months */, 0 /* days */),
		KeyUsage:           x509.KeyUsageKeyAgreement | x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pub := &priv.PublicKey
	certB, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return nil, nil, nil, err
	}
	privB, err := x509.MarshalECPrivateKey(priv)

	cert, err := x509.ParseCertificate(certB)
	if err != nil {
		return nil, nil, nil, err
	}
	// PEM encode the certificate (this is a standard TLS encoding)
	b := pem.Block{Type: "CERTIFICATE", Bytes: certB}
	certB = pem.EncodeToMemory(&b)
	b = pem.Block{Type: "EC PRIVATE KEY", Bytes: privB}
	privB = pem.EncodeToMemory(&b)

	return cert, certB, privB, err
}
