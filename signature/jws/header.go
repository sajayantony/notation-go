package jws

type unprotectedHeader struct {
	TimeStampToken []byte   `json:"timestamp,omitempty"`
	KeyID          string   `json:"kid,omitempty"`
	CertChain      [][]byte `json:"x5c,omitempty"`
}
