package jws

import (
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/notaryproject/notary/v2"
	oci "github.com/opencontainers/image-spec/specs-go/v1"
)

const MediaTypeNotaryPayload = "application/vnd.cncf.notary.signature.v2.payload+json"

const notaryClaimName = "notary.v2"

type notaryClaim struct {
	SubjectManifest  oci.Descriptor   `json:"subjectManifest"`
	SignedAttributes signedAttributes `json:"signedAttrs,omitempty"`
}

type signedAttributes struct {
	Reserved map[string]interface{} `json:"reserved,omitempty"`
	Custom   map[string]interface{} `json:"custom,omitempty"`
}

func packPayload(desc oci.Descriptor, opts *notary.SignOptions) jwt.MapClaims {
	var reservedAttributes map[string]interface{}
	if opts.Identity != "" {
		reservedAttributes = map[string]interface{}{
			"identity": opts.Identity,
		}
	}
	return jwt.MapClaims{
		notaryClaimName: notaryClaim{
			SubjectManifest: oci.Descriptor{
				MediaType:   desc.MediaType,
				Digest:      desc.Digest,
				Size:        desc.Size,
				Annotations: desc.Annotations,
			},
			SignedAttributes: signedAttributes{
				Reserved: reservedAttributes,
				Custom:   opts.Attributes,
			},
		},
		"iat": float64(time.Now().Unix()),
		"exp": float64(opts.Expiry.Unix()),
	}
}
