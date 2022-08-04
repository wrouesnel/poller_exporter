package ping_test

import (
	"net"
	"os/user"
	"testing"
	"time"

	"github.com/wrouesnel/poller_exporter/pkg/pollers/ping"

	. "gopkg.in/check.v1"
)

// Hook up gocheck into the "go test" runner.
func Test(t *testing.T) { TestingT(t) }

type PingSuite struct{}

var _ = Suite(&PingSuite{})

func (s *PingSuite) TestIpV4Ping(c *C) {
	user, err := user.Current()
	c.Assert(err, IsNil)

	if user.Uid == "0" {
		ok, _ := ping.Ping(net.ParseIP("127.0.0.1"), time.Second)
		c.Assert(ok, Equals, true, Commentf("IPv4 ping to localhost failed"))
	} else {
		c.Skip("Skipping ping test since not superuser")
	}
}

func (s *PingSuite) TestIpV6Ping(c *C) {
	user, err := user.Current()
	c.Assert(err, IsNil)

	if user.Uid == "0" {
		ok6, _ := ping.Ping(net.ParseIP("::1"), time.Second)
		c.Assert(ok6, Equals, true, Commentf("IPv6 ping to localhost failed"))
	} else {
		c.Skip("Skipping ping test since not superuser")
	}
}
