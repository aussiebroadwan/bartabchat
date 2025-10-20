package jwtx

// Signer is our interface for anything that can sign JWTs.
type Signer interface {
	Alg() string
	KID() string
	Sign(Claims) (string, error)
	PublicJWK() JWK
	Validate() error
}

// NewSignerRS256 creates an RS256 signer from PEM bytes.
func NewSignerRS256(kid string, pemKey []byte) (Signer, error) {
	return newRS256Signer(kid, pemKey)
}

// NewSignerEdDSA creates an EdDSA signer from PEM bytes.
// Ed25519 keys must be in PKCS8 format.
func NewSignerEdDSA(kid string, pemKey []byte) (Signer, error) {
	return newEdDSASigner(kid, pemKey)
}

// NewSignerES256 creates an ES256 signer from PEM bytes.
// ECDSA P-256 keys must be in PKCS8 format.
func NewSignerES256(kid string, pemKey []byte) (Signer, error) {
	return newES256Signer(kid, pemKey)
}
