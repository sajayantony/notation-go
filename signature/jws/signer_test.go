package jws

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/notaryproject/notary/v2"
	"github.com/opencontainers/go-digest"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
)

func TestSignRawKey(t *testing.T) {
	// Generate a RSA key pair
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	keyID := "test key"

	// Sign with key
	s, err := NewSigner(keyID, key)
	if err != nil {
		t.Fatalf("NewSigner() error = %v", err)
	}
	content := "hello world"
	desc := oci.Descriptor{
		MediaType: "test media type",
		Digest:    digest.Canonical.FromString(content),
		Size:      int64(len(content)),
		Annotations: map[string]string{
			"mode": "debug",
		},
	}
	sOpts := &notary.SignOptions{
		Expiry:   time.Now().UTC().Add(time.Hour),
		Identity: "test.registry.io/test:example",
		Attributes: map[string]interface{}{
			"foo": "bar",
		},
	}
	signature, err := s.Sign(context.Background(), desc, sOpts)
	if err != nil {
		t.Fatalf("Sign() error = %v", err)
	}

	// Verify signature
	vk, err := NewVerificationKey(keyID, &key.PublicKey)
	if err != nil {
		t.Fatalf("NewVerificationKey() error = %v", err)
	}

	v := NewVerifier([]*VerificationKey{vk}, nil)
	var vOpts notary.VerifyOptions
	err = v.Verify(context.Background(), desc, signature, &vOpts)
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}

	if vOpts.ExportIdentity != sOpts.Identity {
		t.Errorf("Identity = %v, want %v", vOpts.ExportIdentity, sOpts.Identity)
	}
	if len(vOpts.ExportAnnotations) != 1 || vOpts.ExportAnnotations["mode"] != "debug" {
		t.Errorf("Annotations = %v, want %v", vOpts.ExportAnnotations, desc.Annotations)
	}
	if len(vOpts.ExportAttributes) != 1 || vOpts.ExportAttributes["foo"] != "bar" {
		t.Errorf("Attributes = %v, want %v", vOpts.ExportAttributes, sOpts.Attributes)
	}
}
