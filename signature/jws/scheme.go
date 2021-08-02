package jws

import (
	"context"
	"errors"

	"github.com/golang-jwt/jwt"
	"github.com/notaryproject/notary/v2"
	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/shizhMSFT/go-jwsutil"
	"github.com/shizhMSFT/go-timestamp"
)

var _ notary.Service = &Scheme{}

type Scheme struct {
	SigningMethod      jwt.SigningMethod
	SigningKey         interface{}
	SigningKeyID       string
	SigningCertChain   [][]byte
	TimeStampAuthority string
}

func (s *Scheme) Sign(ctx context.Context, desc oci.Descriptor, opts *notary.SignOptions) ([]byte, error) {
	if opts == nil {
		return nil, errors.New("missing signing options")
	}
	if s.SigningMethod == nil {
		return nil, errors.New("missing signing method")
	}
	if s.SigningKey == nil {
		return nil, errors.New("missing signing key")
	}
	if s.SigningKeyID == "" && s.SigningCertChain == nil {
		return nil, errors.New("missing signer info")
	}

	// Generate JWT
	payload := packPayload(desc, opts)
	if err := payload.Valid(); err != nil {
		return nil, err
	}
	token := jwt.NewWithClaims(s.SigningMethod, payload)
	token.Header["cty"] = MediaTypeNotaryPayload
	token.Header["crit"] = []string{"cty"}
	compact, err := token.SignedString(s.SigningKey)
	if err != nil {
		return nil, err
	}

	// Generate unsigned header
	header := make(map[string]interface{})
	if s.SigningKeyID != "" {
		header["kid"] = s.SigningKeyID
	}
	if s.SigningCertChain != nil {
		header["x5c"] = s.SigningCertChain
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
		header["timestamp"] = resp.TimeStampToken.FullBytes
	}

	// Convert to JWS JSON serialization
	jwsJSON, err := jwsutil.ConvertCompactToJSON(compact, header)
	if err != nil {
		return nil, err
	}

	return []byte(jwsJSON), nil
}

func (s *Scheme) Verify(ctx context.Context, desc oci.Descriptor, signature []byte, opts *notary.VerifyOptions) error {
	panic("not implemented") // TODO: Implement
}
