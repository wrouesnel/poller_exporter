package certutils

import (
	"crypto/x509"
	"encoding/pem"

	"github.com/pkg/errors"
)

var ErrCouldParsePemCertificateBytes = errors.New("Could not parse bytes as PEM certificate")

// LoadCertificatesFromPem is a helper function used for testing.
func LoadCertificatesFromPem(pemCerts []byte) ([]*x509.Certificate, error) {
	idx := 0
	certs := make([]*x509.Certificate, 0)
	for len(pemCerts) > 0 {
		var block *pem.Block
		block, pemCerts = pem.Decode(pemCerts)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			idx++
			continue
		}

		certBytes := block.Bytes
		cert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			return certs, errors.Wrapf(ErrCouldParsePemCertificateBytes, "error on block %v", idx)
		}

		certs = append(certs, cert)
		idx++
	}
	return certs, nil
}
