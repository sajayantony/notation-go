package jws

import (
	"bytes"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/notaryproject/notary/v2"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/shizhMSFT/go-jwsutil"
	"github.com/shizhMSFT/go-timestamp"
)

var _ notary.Verifier = &Verifier{}

type VerificationKey struct {
	ID        string
	Value     crypto.PublicKey
	Algorithm string
}

func NewVerificationKey(keyID string, key crypto.PublicKey) (*VerificationKey, error) {
	method, err := SigningMethodFromKey(key)
	if err != nil {
		return nil, err
	}
	return &VerificationKey{
		ID:        keyID,
		Value:     key,
		Algorithm: method.Alg(),
	}, nil
}

type Verifier struct {
	Roots *x509.CertPool

	keys map[string]*VerificationKey
}

func NewVerifier(keys []*VerificationKey, roots *x509.CertPool) *Verifier {
	indexedKeys := make(map[string]*VerificationKey)
	for _, key := range keys {
		if key.ID != "" {
			indexedKeys[key.ID] = key
		}
	}
	return &Verifier{
		Roots: roots,
		keys:  indexedKeys,
	}
}

func (v *Verifier) Verify(ctx context.Context, desc oci.Descriptor, signature []byte, opts *notary.VerifyOptions) error {
	if opts == nil {
		return errors.New("missing verification options")
	}

	// Unpack envelope
	envelope, err := jwsutil.ParseJSON(string(signature))
	if err != nil {
		return err
	}
	if len(envelope.Signatures) != 1 {
		return errors.New("envelope should contains exactly 1 signature")
	}
	sig := envelope.CompleteSignature()
	compact := sig.SerializeCompact()

	// Get verification key
	key, err := v.getVerificationKey(sig.Unprotected, sig.Signature.Signature)
	if err != nil {
		return err
	}

	// Verify JWT
	var claims payload
	_, err = jwt.ParseWithClaims(compact, &claims, func(t *jwt.Token) (interface{}, error) {
		if alg := t.Method.Alg(); alg != key.Algorithm {
			return nil, fmt.Errorf("Unexpected signing method: %v", alg)
		}
		return key.Value, nil
	})
	if err != nil {
		return err
	}

	// Verify required claims
	now := time.Now().Unix()
	if !claims.VerifyIssuedAt(now, true) {
		return errors.New("missing iat in token")
	}
	if !claims.VerifyExpiresAt(now, true) {
		return errors.New("missing exp in token")
	}

	// Verify notary claim
	return verifyNotaryClaim(claims.Notary, desc, opts)
}

func (v *Verifier) getVerificationKey(unprotected json.RawMessage, compact string) (*VerificationKey, error) {
	var header unprotectedHeader
	if err := json.Unmarshal(unprotected, &header); err != nil {
		return nil, err
	}

	if key, ok := v.keys[header.KeyID]; ok {
		return key, nil
	}

	return v.getVerificationKeyFromCertChain(header.CertChain, header.TimeStampToken, compact)
}

func (v *Verifier) getVerificationKeyFromCertChain(certChain [][]byte, timeStampToken []byte, signature string) (*VerificationKey, error) {
	if len(certChain) == 0 {
		return nil, errors.New("missing verification info")
	}

	certs := make([]*x509.Certificate, 0, len(certChain))
	for _, certBytes := range certChain {
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	intermediates := x509.NewCertPool()
	for _, cert := range certs[1:] {
		intermediates.AddCert(cert)
	}
	verifyOpts := x509.VerifyOptions{
		Intermediates: intermediates,
		Roots:         v.Roots,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}
	cert := certs[0]
	if _, err := cert.Verify(verifyOpts); err != nil {
		if certErr, ok := err.(x509.CertificateInvalidError); !ok || certErr.Reason != x509.Expired || timeStampToken == nil {
			return nil, err
		}
		decodedSignature, err := jwt.DecodeSegment(signature)
		if err != nil {
			return nil, err
		}
		verifyOpts.CurrentTime, err = getTimeFromTST(timeStampToken, decodedSignature)
		if err != nil {
			return nil, err
		}
		if _, err := cert.Verify(verifyOpts); err != nil {
			return nil, err
		}
	}

	method, err := SigningMethodFromKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}

	return &VerificationKey{
		Value:     cert.PublicKey,
		Algorithm: method.Alg(),
	}, nil
}

func getTimeFromTST(tst, message []byte) (time.Time, error) {
	resp := timestamp.Response{
		TimeStampToken: asn1.RawValue{
			FullBytes: tst,
		},
	}
	token, err := resp.TimeStampTokenInfo()
	if err != nil {
		return time.Time{}, err
	}
	if err := verifyMessage(token.MessageImprint, message); err != nil {
		return time.Time{}, err
	}
	return token.GenTime, nil
}

func verifyMessage(imprint timestamp.MessageImprint, message []byte) error {
	hash, ok := timestamp.ConvertToHash(imprint.HashAlgorithm.Algorithm)
	if !ok {
		return errors.New("hash algorithm not recognized")
	}
	h := hash.New()
	if _, err := h.Write(message); err != nil {
		return err
	}
	digest := h.Sum(nil)
	if !bytes.Equal(digest, imprint.HashedMessage) {
		return errors.New("digest mismatch")
	}
	return nil
}

func verifyNotaryClaim(claim notaryClaim, actualDesc oci.Descriptor, opts *notary.VerifyOptions) error {
	expectedDesc := claim.SubjectManifest
	if actualDesc.MediaType != expectedDesc.MediaType {
		return errors.New("mismatch media type")
	}
	if actualDesc.Size != expectedDesc.Size {
		return errors.New("mismatch size")
	}
	if actualDesc.Digest != expectedDesc.Digest {
		return errors.New("mismatch digest")
	}

	opts.ExportIdentity, _ = claim.SignedAttributes.Reserved["identity"].(string)
	opts.ExportAnnotations = expectedDesc.Annotations
	opts.ExportAttributes = claim.SignedAttributes.Custom

	return nil
}
