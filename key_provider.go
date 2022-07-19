package asn

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"

	"github.com/lestrrat-go/jwx/v2/jws"
)

type verifiedKey struct {
	name   []byte
	pubkey any
}

// KeyProvider implements jws.KeyProvider.
// Once pubkey verified,
type KeyProvider struct {
	trusted verifiedKey
	fetcher RootCAFetcher
}

// NewKeyProvider returns a new KeyProvider.
func NewKeyProvider(fetcher RootCAFetcher) *KeyProvider {
	return &KeyProvider{
		trusted: verifiedKey{},
		fetcher: fetcher,
	}
}

// FetchKeys extracts the public key from the y5c field to verify the certificate according to https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6.
// Treat the chain that matches the root certificate fetched by RootCAFetcher as the root certificate.
func (p *KeyProvider) FetchKeys(ctx context.Context, sink jws.KeySink, sig *jws.Signature, msg *jws.Message) error {
	headers := sig.ProtectedHeaders()
	certs := headers.X509CertChain()
	verifyOpts := x509.VerifyOptions{
		Roots:         x509.NewCertPool(),
		Intermediates: x509.NewCertPool(),
	}
	var isApple bool
	var label []byte
	var key *x509.Certificate
	for i := 0; i < certs.Len(); i++ {
		chain, _ := certs.Get(i)
		if bytes.Equal(p.trusted.name, chain) {
			sink.Key(headers.Algorithm(), p.trusted.pubkey)
			return nil
		}
		dbuf := make([]byte, base64.StdEncoding.DecodedLen(len(chain)))
		n, err := base64.StdEncoding.Decode(dbuf, chain)
		if err != nil {
			return err
		}
		cert, err := x509.ParseCertificate(dbuf[:n])
		if err != nil {
			return err
		}
		switch i {
		case 0:
			label = chain
			key = cert
		default:
			hasRoot, err := p.match(ctx, chain)
			if err != nil {
				return err
			}
			if hasRoot {
				isApple = true
				verifyOpts.Roots.AddCert(cert)
			} else {
				verifyOpts.Intermediates.AddCert(cert)
			}
		}
	}
	if !isApple {
		return errors.New("certificate is not from Apple")
	}
	if _, err := key.Verify(verifyOpts); err != nil {
		return err
	}
	p.trusted = verifiedKey{
		name:   label,
		pubkey: key.PublicKey,
	}
	sink.Key(headers.Algorithm(), key.PublicKey)
	return nil
}

func (p *KeyProvider) match(ctx context.Context, chain []byte) (bool, error) {
	roots, err := p.fetcher.Fetch(ctx)
	if err != nil {
		return false, err
	}
	for _, root := range roots {
		if bytes.Equal(root, chain) {
			return true, nil
		}
	}
	return false, nil
}
