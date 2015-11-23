package ping

import (
	"testing"
	"github.com/stretchr/testify/assert"
	"time"
	"net"
	"flag"
	"os/user"
	"fmt"
)

func init() {
	flag.Parse()
}

func TestPing(t *testing.T) {
	assert := assert.New(t)
    
    user, err := user.Current()
    assert.Nil(err)
    if user.Uid == "0" {
	    ok, _ := Ping(net.ParseIP("127.0.0.1"), time.Second)
	    assert.True(ok, "Localhost IPv4 Ping")

	    ok6, _ := Ping(net.ParseIP("::1"), time.Second)
	    assert.True(ok6, "Localhost IPv6 Ping")
	} else {
	    fmt.Println("Skipping ping test since not superuser")
	}
}
