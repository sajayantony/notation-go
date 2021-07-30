package notary

import (
	"context"
	"time"

	oci "github.com/opencontainers/image-spec/specs-go/v1"
)

type SignOptions struct {
	Expiry     time.Time
	Identity   string
	Attributes map[string]interface{}
}

type VerifyOptions struct {
	Annotations map[string]string
	Attributes  map[string]interface{}
}

type Service interface {
	Sign(ctx context.Context, desc oci.Descriptor, opts *SignOptions) ([]byte, error)
	Verify(ctx context.Context, desc oci.Descriptor, signature []byte, opts *VerifyOptions) error
}
