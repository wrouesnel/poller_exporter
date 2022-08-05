//nolint:forcetypeassert
package config_test

import (
	"crypto/x509"
	"io/ioutil"
	"reflect"
	"testing"
	"unsafe"

	"github.com/wrouesnel/poller_exporter/pkg/certutils"
	"github.com/wrouesnel/poller_exporter/pkg/config"
	"github.com/wrouesnel/poller_exporter/pkg/errutils"
	. "gopkg.in/check.v1"
	"gopkg.in/yaml.v3"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type TLSCACertsSuite struct{}

var _ = Suite(&TLSCACertsSuite{})

func GetPoolCertificates(pool *x509.CertPool) []*x509.Certificate {
	poolReflect := reflect.ValueOf(pool).Elem()
	lazyCerts := poolReflect.FieldByName("lazyCerts")
	poolCerts := make([]*x509.Certificate, 0)

	for i := 0; i < lazyCerts.Len(); i++ {
		methodInterface := lazyCerts.Index(i)
		methodField := methodInterface.FieldByName("getCert")
		callable := reflect.NewAt(methodField.Type(), unsafe.Pointer(methodField.UnsafeAddr())).Elem()
		certs := callable.Call(nil)[0].Interface().(*x509.Certificate)
		poolCerts = append(poolCerts, certs)
	}
	return poolCerts
}

func (s *TLSCACertsSuite) TestLoadFullExample(c *C) {
	data := errutils.Must(ioutil.ReadFile("test_data/tls_cacerts/system_file_inline.yml"))
	pool := new(config.TLSCertificatePool)

	err := yaml.Unmarshal(data, pool)
	c.Assert(err, IsNil)

	poolCerts := GetPoolCertificates(pool.CertPool)

	// Check the inline and file certs are there
	otherCert := errutils.Must(certutils.LoadCertificatesFromPem(errutils.Must(ioutil.ReadFile("test_data/tls_cacerts/other.crt"))))[0]
	someCert := errutils.Must(certutils.LoadCertificatesFromPem(errutils.Must(ioutil.ReadFile("test_data/tls_cacerts/some.crt"))))[0]

	otherCertFound := false
	someCertFound := false

	for _, cert := range poolCerts {
		if cert.Equal(otherCert) {
			otherCertFound = true
		}

		if cert.Equal(someCert) {
			someCertFound = true
		}
	}

	c.Check(otherCertFound, Equals, true)
	c.Check(someCertFound, Equals, true)
}

func (s *TLSCACertsSuite) TestLoadNoSystem(c *C) {
	data := errutils.Must(ioutil.ReadFile("test_data/tls_cacerts/file_inline.yml"))
	pool := new(config.TLSCertificatePool)

	err := yaml.Unmarshal(data, pool)
	c.Assert(err, IsNil)

	poolCerts := GetPoolCertificates(pool.CertPool)

	// Check the inline and file certs are there
	otherCert := errutils.Must(certutils.LoadCertificatesFromPem(errutils.Must(ioutil.ReadFile("test_data/tls_cacerts/other.crt"))))[0]
	someCert := errutils.Must(certutils.LoadCertificatesFromPem(errutils.Must(ioutil.ReadFile("test_data/tls_cacerts/some.crt"))))[0]

	otherCertFound := false
	someCertFound := false

	for _, cert := range poolCerts {
		if cert.Equal(otherCert) {
			otherCertFound = true
		}

		if cert.Equal(someCert) {
			someCertFound = true
		}
	}

	c.Check(otherCertFound, Equals, true)
	c.Check(someCertFound, Equals, true)
	c.Check(len(poolCerts), Equals, 2)
}

func (s *TLSCACertsSuite) TestLoadNone(c *C) {
	data := errutils.Must(ioutil.ReadFile("test_data/tls_cacerts/none.yml"))
	pool := new(config.TLSCertificatePool)

	err := yaml.Unmarshal(data, pool)
	c.Assert(err, IsNil)

	poolCerts := GetPoolCertificates(pool.CertPool)
	c.Check(len(poolCerts), Equals, 0)
}
