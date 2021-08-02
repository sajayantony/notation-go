module github.com/notaryproject/notary/v2

go 1.16

require (
	github.com/golang-jwt/jwt v3.2.2+incompatible
	github.com/opencontainers/artifacts v0.0.0-20210209205009-a282023000bd
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.0.1
	github.com/shizhMSFT/go-jwsutil v0.1.0
	github.com/shizhMSFT/go-timestamp v0.1.0
)

replace github.com/opencontainers/artifacts => github.com/aviral26/artifacts v0.0.3
