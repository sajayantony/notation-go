package simple

import (
	"crypto"
	"crypto/x509"

	"github.com/notaryproject/notary/v2"
	"github.com/notaryproject/notary/v2/signature/jws"
)

type service struct {
	notary.Signer
	notary.Verifier
}

// NewJWSService create a simple signing service backend by JWS.
func NewJWSService(signingKey crypto.PrivateKey, signingCerts []*x509.Certificate, roots *x509.CertPool) (notary.Service, error) {
	signer, err := jws.NewSignerFromCerts(signingCerts, signingKey)
	if err != nil {
		return nil, err
	}
	return &service{
		Signer:   signer,
		Verifier: jws.NewVerifier(nil, roots),
	}, nil
}
