//nolint:forcetypeassert
package config_test

import (
	"crypto/x509"
	"io/ioutil"
	"reflect"
	"regexp"
	"testing"
	"time"
	"unsafe"

	"github.com/prometheus/common/model"
	"github.com/samber/lo"
	"github.com/wrouesnel/poller_exporter/pkg/certutils"
	"github.com/wrouesnel/poller_exporter/pkg/config"
	"gopkg.in/yaml.v3"

	. "gopkg.in/check.v1"
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

func (s *TLSCACertsSuite) loadCertsFile(c *C, filename string) *x509.CertPool {
	data := lo.Must(ioutil.ReadFile(filename))
	intfMap := []interface{}{}
	c.Check(yaml.Unmarshal(data, &intfMap), IsNil, Commentf("YAML decode failed"))

	pool := new(config.TLSCertificatePool)
	decoder, err := config.Decoder(pool, false)
	c.Assert(err, IsNil, Commentf("Config decoder initialization failed"))

	err = decoder.Decode(intfMap)
	c.Assert(err, IsNil, Commentf("Config decoding failed"))

	return pool.CertPool
}

func (s *TLSCACertsSuite) TestLoadFullExample(c *C) {
	pool := s.loadCertsFile(c, "test_data/tls_cacerts/system_file_inline.yml")
	poolCerts := GetPoolCertificates(pool)

	// Check the inline and file certs are there
	otherCert := lo.Must(certutils.LoadCertificatesFromPem(lo.Must(ioutil.ReadFile("test_data/tls_cacerts/other.crt"))))[0]
	someCert := lo.Must(certutils.LoadCertificatesFromPem(lo.Must(ioutil.ReadFile("test_data/tls_cacerts/some.crt"))))[0]

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
	pool := s.loadCertsFile(c, "test_data/tls_cacerts/file_inline.yml")
	poolCerts := GetPoolCertificates(pool)

	// Check the inline and file certs are there
	otherCert := lo.Must(certutils.LoadCertificatesFromPem(lo.Must(ioutil.ReadFile("test_data/tls_cacerts/other.crt"))))[0]
	someCert := lo.Must(certutils.LoadCertificatesFromPem(lo.Must(ioutil.ReadFile("test_data/tls_cacerts/some.crt"))))[0]

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
	pool := s.loadCertsFile(c, "test_data/tls_cacerts/none.yml")
	poolCerts := GetPoolCertificates(pool)
	c.Check(len(poolCerts), Equals, 0)
}

type ConfigOverrideSuite struct{}

var _ = Suite(&ConfigOverrideSuite{})

func (cos *ConfigOverrideSuite) TestTLSOverride(c *C) {
	conf, err := config.LoadFromFile("test_data/config_override/config_override_tls.yml")
	c.Assert(err, IsNil, Commentf("%v", err))

	globalCerts := GetPoolCertificates(conf.HostDefault.ServiceDefaults.TLSCACerts.CertPool)
	systemPool := GetPoolCertificates(lo.Must(x509.SystemCertPool()))

	hostConfigs := map[string]*config.HostConfig{}

	for _, host := range conf.Hosts {
		hostConfigs[host.Hostname] = host
	}

	// Check TLS CA certs looks like the system pool
	c.Check(len(globalCerts), Equals, len(systemPool))

	// Check the host with a custom cert has it
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-custom"].BasicChecks[0].TLSCACerts.CertPool)),
		Equals, 1)
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-custom"].ChallengeResponseChecks[0].TLSCACerts.CertPool)),
		Equals, 1)
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-custom"].HTTPChecks[0].TLSCACerts.CertPool)),
		Equals, 1)

	// Check the host with no certs has the globals
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-default"].BasicChecks[0].TLSCACerts.CertPool)),
		Equals, len(globalCerts))
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-default"].ChallengeResponseChecks[0].TLSCACerts.CertPool)),
		Equals, len(globalCerts))
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-default"].HTTPChecks[0].TLSCACerts.CertPool)),
		Equals, len(globalCerts))
}

func (cos *ConfigOverrideSuite) TestTLSOverrideWithNoSpecifiedDefaults(c *C) {
	conf, err := config.LoadFromFile("test_data/config_override/config_override_tlsdefault.yml")
	c.Assert(err, IsNil, Commentf("%v", err))

	globalCerts := GetPoolCertificates(conf.HostDefault.ServiceDefaults.TLSCACerts.CertPool)
	systemPool := GetPoolCertificates(lo.Must(x509.SystemCertPool()))

	hostConfigs := map[string]*config.HostConfig{}

	for _, host := range conf.Hosts {
		hostConfigs[host.Hostname] = host
	}

	// Check TLS CA certs looks like the system pool
	c.Check(len(globalCerts), Equals, len(systemPool))

	// Check the host with a custom cert has it
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-custom"].BasicChecks[0].TLSCACerts.CertPool)),
		Equals, 1)
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-custom"].ChallengeResponseChecks[0].TLSCACerts.CertPool)),
		Equals, 1)
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-custom"].HTTPChecks[0].TLSCACerts.CertPool)),
		Equals, 1)

	// Check the host with no certs has the globals
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-default"].BasicChecks[0].TLSCACerts.CertPool)),
		Equals, len(globalCerts))
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-default"].ChallengeResponseChecks[0].TLSCACerts.CertPool)),
		Equals, len(globalCerts))
	c.Check(len(GetPoolCertificates(hostConfigs["host-with-default"].HTTPChecks[0].TLSCACerts.CertPool)),
		Equals, len(globalCerts))
}

type ConfigExpected struct{}

var _ = Suite(&ConfigExpected{})

// TestCompleteConfig loads poller_exporter.complete.yml and checks the loaded file matches.
func (ce *ConfigExpected) TestCompleteConfig(c *C) {
	systemPool := GetPoolCertificates(lo.Must(x509.SystemCertPool()))

	conf, err := config.LoadFromFile("../../poller_exporter.complete.yml")
	c.Assert(err, IsNil, Commentf("%v", err))

	c.Check(conf.Web.TelemetryPath, Equals, "/metrics")
	c.Check(conf.Web.ReadHeaderTimeout, Equals, model.Duration(time.Second))

	c.Check(conf.Web.Listen[0].String(), Equals, lo.Must(config.NewURL("unix:///var/run/server.socket")).String())
	c.Check(conf.Web.Listen[1].String(), Equals, lo.Must(config.NewURL("tcp://0.0.0.0:9115")).String())
	c.Check(conf.Web.Listen[2].String(), Equals, lo.Must(config.NewURL("tcps://0.0.0.0:9115?tlscert=/path/to/file/in/pem/format.crt&tlskey=/path/to/file/in/pem/format.pem")).String())
	c.Check(conf.Web.Listen[3].String(), Equals, lo.Must(config.NewURL("unixs:///var/run/server.socket?tlscert=/path/to/file/in/pem/format.crt&tlskey=/path/to/file/in/pem/format.pem")).String())
	c.Check(conf.Web.Listen[4].String(), Equals, lo.Must(config.NewURL("tcps://0.0.0.0:9115?tlscert=/path/to/file/in/pem/format.crt&tlskey=/path/to/file/in/pem/format.pem&tlsclientca=/path/to/cert")).String())

	c.Check(conf.Web.Auth.BasicAuthCredentials[0].Username, Equals, "admin")
	c.Check(conf.Web.Auth.BasicAuthCredentials[0].Password, Equals, "my-pass")

	c.Check(conf.Collector.MaxConnections, Equals, 50)

	c.Check(conf.HostDefault.PollFrequency, Equals, model.Duration(time.Second*30))
	c.Check(conf.HostDefault.PingDisable, Equals, false)
	c.Check(conf.HostDefault.PingTimeout, Equals, model.Duration(time.Second))
	c.Check(conf.HostDefault.PingCount, Equals, uint64(3))

	c.Check(conf.HostDefault.ExtraLabels, Not(IsNil))
	c.Check(conf.HostDefault.ExtraLabels["host_label1"], Equals, "label1-value")
	c.Check(conf.HostDefault.ExtraLabels["host_label2"], Equals, "label2-value")

	c.Check(conf.HostDefault.ServiceDefaults.Timeout, Equals, model.Duration(time.Second*10))
	c.Check(conf.HostDefault.ServiceDefaults.MaxBytes, Equals, uint64(4096))
	c.Check(conf.HostDefault.ServiceDefaults.TLSEnable, Equals, false)
	c.Check(conf.HostDefault.ServiceDefaults.TLSVerifyFailOk, Equals, false)

	c.Check(conf.HostDefault.ServiceDefaults.ExtraLabels, Not(IsNil))
	c.Check(conf.HostDefault.ServiceDefaults.ExtraLabels["service_label1"], Equals, "label1-value")
	c.Check(conf.HostDefault.ServiceDefaults.ExtraLabels["service_label2"], Equals, "label2-value")

	c.Check(len(GetPoolCertificates(conf.HostDefault.ServiceDefaults.TLSCACerts.CertPool)), Equals, len(systemPool)+2, Commentf("Check TLS CA certs looks like the system pool + 2 extra certs"))

	// Start checking hosts - convert to map up front
	hostConfigs := map[string]*config.HostConfig{}
	for _, host := range conf.Hosts {
		hostConfigs[host.Hostname] = host
	}

	hostConf := hostConfigs["myhost"]
	c.Check(hostConf.Hostname, Equals, "myhost")
	c.Check(hostConf.PollFrequency, Equals, model.Duration(2*time.Second))
	c.Check(hostConf.PingDisable, Equals, true)
	c.Check(hostConf.PingTimeout, Equals, model.Duration(5*time.Second))
	c.Check(hostConf.PingCount, Equals, uint64(2))

	c.Check(hostConf.ServiceDefaults.Timeout, Equals, model.Duration(time.Second*9))
	c.Check(hostConf.ServiceDefaults.MaxBytes, Equals, uint64(1024))
	c.Check(hostConf.ServiceDefaults.TLSEnable, Equals, true)
	c.Check(len(GetPoolCertificates(hostConf.ServiceDefaults.TLSCACerts.CertPool)), Equals, 1, Commentf("Check single default cert"))

	c.Check(hostConf.ServiceDefaults.ExtraLabels, Not(IsNil))
	c.Check(hostConf.ExtraLabels["host_label1"], Equals, "some-other-value")
	c.Check(hostConf.ExtraLabels["host_label2"], Equals, "label2-value")

	c.Check(hostConf.ServiceDefaults.ExtraLabels["service_label1"], Equals, "Changed")
	c.Check(hostConf.ServiceDefaults.ExtraLabels["service_label2"], Equals, "label2-value")

	basicChecks := hostConf.BasicChecks[0]
	c.Check(basicChecks.Name, Equals, "SMTP")
	c.Check(basicChecks.Protocol, Equals, "tcp")
	c.Check(basicChecks.Port, Equals, uint64(465))
	c.Check(basicChecks.Timeout, Equals, model.Duration(5*time.Second))
	c.Check(basicChecks.TLSEnable, Equals, true)
	c.Check(basicChecks.TLSVerifyFailOk, Equals, true)
	// The config has an identical cert specified twice, so we should load it exactly once.
	c.Check(len(basicChecks.TLSCertificatePin.GetCerts()), Equals, 1)
	// Double check against the pem file
	pinnedCertSource := lo.Must(certutils.LoadCertificatesFromPem(lo.Must(ioutil.ReadFile("test_data/localhost.crt"))))[0].Raw
	c.Check(basicChecks.TLSCertificatePin.GetCerts()[0].Raw, DeepEquals, pinnedCertSource)

	basicChecks.TLSCertificatePin.GetCerts()

	serviceCerts := GetPoolCertificates(basicChecks.TLSCACerts.CertPool)
	c.Check(len(serviceCerts), Equals, 1)

	c.Check(basicChecks.ExtraLabels["host_label1"], Equals, "This label is reinstated despite the service setting")
	//c.Check(basicChecks.ExtraLabels["host_label2"], Equals, "label2-value")
	c.Check(basicChecks.ExtraLabels["service_label1"], Equals, "Changed")
	c.Check(basicChecks.ExtraLabels["service_label2"], Equals, "Changed on the service")

	crChecks := hostConf.ChallengeResponseChecks[0]
	c.Check(crChecks.Name, Equals, "CustomDaemon")
	c.Check(crChecks.Protocol, Equals, "tcp")
	c.Check(crChecks.Port, Equals, uint64(22))
	c.Check(crChecks.Timeout, Equals, model.Duration(6*time.Second))
	c.Check(crChecks.TLSEnable, Equals, false)
	c.Check(len(GetPoolCertificates(crChecks.TLSCACerts.CertPool)), Equals, 2, Commentf("challenge_response has more certs"))

	c.Check(crChecks.ExtraLabels["host_label1"], Equals, "You can do this, but shouldn't")
	//c.Check(crChecks.ExtraLabels["host_label2"], Equals, "label2-value")
	c.Check(crChecks.ExtraLabels["service_label1"], Equals, "Changed")
	c.Check(crChecks.ExtraLabels["service_label2"], Equals, "CR service")

	c.Check(*crChecks.ChallengeString, Equals, "MY_UNIQUE_HEADER")
	c.Check([]byte(crChecks.ChallengeBinary), DeepEquals, []byte{114, 149, 9, 49, 56, 189, 30, 220, 186, 59, 139, 28, 127, 66, 178, 97})
	c.Check(crChecks.ResponseRegex.String(), Equals, regexp.MustCompile("RESPONSE_HEADER").String())
	c.Check(*crChecks.ResponseLiteral, Equals, "literal-value")
	c.Check([]byte(crChecks.ResponseBinary), DeepEquals, []byte{114, 149, 9, 49, 56, 189, 30, 220, 186, 59, 139, 28, 127, 66, 178, 97})
	c.Check(crChecks.MaxBytes, Equals, uint64(65535))

	httpChecks := hostConf.HTTPChecks[0]
	c.Check(httpChecks.Name, Equals, "MyHTTPServer")
	c.Check(httpChecks.Protocol, Equals, "tcp")
	c.Check(httpChecks.Port, Equals, uint64(443))
	c.Check(httpChecks.Timeout, Equals, model.Duration(50*time.Second))
	c.Check(httpChecks.TLSEnable, Equals, true)

	httpServiceCerts := GetPoolCertificates(httpChecks.TLSCACerts.CertPool)
	c.Check(len(httpServiceCerts), Equals, 1)

	//c.Check(httpChecks.ExtraLabels["host_label1"], Equals, "label1-value")
	c.Check(httpChecks.ExtraLabels["host_label2"], Equals, "You can do this, but shouldn't")
	c.Check(httpChecks.ExtraLabels["service_label1"], Equals, "HTTP service")
	c.Check(httpChecks.ExtraLabels["service_label2"], Equals, "label2-value")

	c.Check(*httpChecks.ChallengeString, Equals, "some-data")
	c.Check([]byte(httpChecks.ChallengeBinary), DeepEquals, []byte{114, 149, 9, 49, 56, 189, 30, 220, 186, 59, 139, 28, 127, 66, 178, 97})
	c.Check(httpChecks.ResponseRegex.String(), Equals, regexp.MustCompile("^<field-tag>").String())
	c.Check(*httpChecks.ResponseLiteral, Equals, "<html>")
	c.Check([]byte(httpChecks.ResponseBinary), DeepEquals, []byte{114, 149, 9, 49, 56, 189, 30, 220, 186, 59, 139, 28, 127, 66, 178, 97})
	c.Check(httpChecks.MaxBytes, Equals, uint64(131072))

	c.Check(httpChecks.Verb, Equals, config.HTTPVerb("GET"))
	c.Check(httpChecks.URL.String(), Equals, "http://vhost/query-path?with_paramters=1")
	testRange := config.HTTPStatusRange{}
	c.Check(testRange.UnmarshalText([]byte("200 201 300-399")), IsNil)
	c.Check(httpChecks.SuccessStatuses, DeepEquals, testRange)
	c.Check(httpChecks.RequestAuth.BasicAuth.Username, Equals, "monitor")
	c.Check(httpChecks.RequestAuth.BasicAuth.Password, Equals, "monitoring")
}
