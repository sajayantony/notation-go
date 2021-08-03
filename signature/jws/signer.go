package jws

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"

	"github.com/golang-jwt/jwt"
	"github.com/notaryproject/notary/v2"
	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/shizhMSFT/go-jwsutil"
	"github.com/shizhMSFT/go-timestamp"
)

var _ notary.Signer = &Signer{}

type Signer struct {
	Method             jwt.SigningMethod
	Key                crypto.PrivateKey
	KeyID              string
	CertChain          [][]byte
	TimeStampAuthority string
}

func NewSigner(keyID string, key crypto.PrivateKey) (*Signer, error) {
	if keyID == "" {
		return nil, errors.New("missing signer info")
	}

	method, err := SigningMethodFromKey(key)
	if err != nil {
		return nil, err
	}

	return &Signer{
		Method: method,
		Key:    key,
		KeyID:  keyID,
	}, nil
}

func NewSignerFromCerts(certs []*x509.Certificate, key crypto.PrivateKey) (*Signer, error) {
	if len(certs) == 0 {
		return nil, errors.New("missing signer info")
	}

	method, err := SigningMethodFromKey(key)
	if err != nil {
		return nil, err
	}
	rawCerts := make([][]byte, 0, len(certs))
	for _, cert := range certs {
		rawCerts = append(rawCerts, cert.Raw)
	}

	return &Signer{
		Method:    method,
		Key:       key,
		CertChain: rawCerts,
	}, nil
}

func (s *Signer) Sign(ctx context.Context, desc oci.Descriptor, opts *notary.SignOptions) ([]byte, error) {
	if opts == nil {
		return nil, errors.New("missing signing options")
	}
	if s.Method == nil {
		return nil, errors.New("missing signing method")
	}
	if s.Key == nil {
		return nil, errors.New("missing signing key")
	}
	if s.KeyID == "" && s.CertChain == nil {
		return nil, errors.New("missing signer info")
	}

	// Generate JWT
	payload := packPayload(desc, opts)
	if err := payload.Valid(); err != nil {
		return nil, err
	}
	token := jwt.NewWithClaims(s.Method, payload)
	token.Header["cty"] = MediaTypeNotaryPayload
	token.Header["crit"] = []string{"cty"}
	delete(token.Header, "typ")
	compact, err := token.SignedString(s.Key)
	if err != nil {
		return nil, err
	}

	// Generate unsigned header
	header := unprotectedHeader{
		KeyID:     s.KeyID,
		CertChain: s.CertChain,
	}

	// Timestamp JWT
	if s.TimeStampAuthority != "" {
		req, err := timestamp.NewRequest(digest.FromString(compact))
		if err != nil {
			return nil, err
		}
		req.CertReq = true

		ts := timestamp.NewHTTPTimestamper(nil, s.TimeStampAuthority)
		resp, err := ts.Timestamp(ctx, req)
		if err != nil {
			return nil, err
		}
		if resp.Status.Status != timestamp.PKIStatusGranted {
			return nil, errors.New("timestamp: " + resp.Status.StatusString)
		}
		header.TimeStampToken = resp.TimeStampToken.FullBytes
	}

	// Convert to JWS JSON serialization
	jwsJSON, err := jwsutil.ConvertCompactToJSON(compact, header)
	if err != nil {
		return nil, err
	}

	return []byte(jwsJSON), nil
}
