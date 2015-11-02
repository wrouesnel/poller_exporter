package ping

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"time"
	"net"
	"flag"
)

func init() {
	flag.Parse()
}

func TestPing(t *testing.T) {
	assert := assert.New(t)

	ok, _ := Ping(net.ParseIP("127.0.0.1"), time.Second)
	assert.True(ok, "Localhost IPv4 Ping")

	ok6, _ := Ping(net.ParseIP("::1"), time.Second)
	assert.True(ok6, "Localhost IPv6 Ping")
}