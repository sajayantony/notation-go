package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"os"
)

// ReadCertificateFile reads a certificate PEM file
func ReadCertificateFile(path string) ([]*x509.Certificate, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var certs []*x509.Certificate
	block, rest := pem.Decode(raw)
	for block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
		block, rest = pem.Decode(rest)
	}
	return certs, nil
}
