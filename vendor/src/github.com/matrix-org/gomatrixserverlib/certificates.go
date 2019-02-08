package gomatrixserverlib

import (
	"crypto/x509"
)

// IsValidCertificate checks if the given x509 certificate can be verified using
// system root CAs and an optional pool of intermediate CAs.
func IsValidCertificate(serverNames []ServerName, c *x509.Certificate, intermediates *x509.CertPool) (bool, error) {
	for _, serverName := range serverNames {
		verificationOpts := x509.VerifyOptions{
			DNSName:       string(serverName),
			Intermediates: intermediates,
		}
		roots, err := c.Verify(verificationOpts)
		if err != nil {
			return false, err
		} else if len(roots) > 0 {
			return true, err
		}
	}

	return false, nil
}
