package ping

import (
	"bytes"
	"net"
	"os"
	"sync"
	"time"

	"github.com/pkg/errors"

	"go.uber.org/zap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

//nolint:gochecknoglobals
var (
	icmpSequence      uint16
	icmpSequenceMutex sync.Mutex
)

func isIPv4(ip net.IP) bool {
	return len(ip.To4()) == net.IPv4len
}

func isIPv6(ip net.IP) bool {
	return len(ip) == net.IPv6len
}

func getICMPSequence() uint16 {
	icmpSequenceMutex.Lock()
	defer icmpSequenceMutex.Unlock()
	icmpSequence++
	return icmpSequence
}

// Sends a single ICMP echo to an IP and returns success and latency information.
// Borrowed from BrianBrazil's blackbox exporter
//nolint: funlen,gocyclop,cyclop,nonamedreturns
func Ping(ip net.IP, maxRTT time.Duration) (success bool, latency time.Duration) {
	log := zap.L()
	deadline := time.Now().Add(maxRTT)

	var socket *icmp.PacketConn
	var err error
	//nolint:gocritic
	if isIPv4(ip) {
		socket, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	} else if isIPv6(ip) {
		socket, err = icmp.ListenPacket("ip6:ipv6-icmp", "::")
	} else {
		log.Error("IP did not match any known types?")
		return
	}

	if err != nil {
		log.Error("Error listening to socket", zap.Error(err))
		return
	}
	defer socket.Close()

	seq := getICMPSequence()
	pid := os.Getpid() & 0xffff //nolint:gomnd

	// Build the packet
	var icmpMessage icmp.Message
	//nolint:gocritic
	if isIPv4(ip) {
		icmpMessage = icmp.Message{
			Type:     ipv4.ICMPTypeEcho,
			Code:     0,
			Checksum: 0,
			Body: &icmp.Echo{
				ID: pid, Seq: int(seq),
				Data: []byte("poller_exporter"),
			},
		}
	} else if isIPv6(ip) {
		icmpMessage = icmp.Message{
			Type:     ipv6.ICMPTypeEchoRequest,
			Code:     0,
			Checksum: 0,
			Body: &icmp.Echo{
				ID: pid, Seq: int(seq),
				Data: []byte("poller_exporter"),
			},
		}
	} else {
		log.Error("IP did not match any known types?")
		return
	}

	icmpMessageBytes, err := icmpMessage.Marshal(nil)
	if err != nil {
		log.Error("Error marshalling packet", zap.String("ip_address", ip.String()), zap.Error(err))
		return
	}

	sendTime := time.Now()

	dst := &net.IPAddr{IP: ip}

	if _, err := socket.WriteTo(icmpMessageBytes, dst); err != nil {
		log.Error("Error writing to socket", zap.String("ip_address", ip.String()), zap.Error(err))
		return
	}

	// Reply should be the same except for the message type].
	//nolint:gocritic
	if isIPv4(ip) {
		icmpMessage.Type = ipv4.ICMPTypeEchoReply
	} else if isIPv6(ip) {
		icmpMessage.Type = ipv6.ICMPTypeEchoReply
	} else {
		log.Error("IP did not match any known types?")
		return
	}

	icmpMessageBytes, err = icmpMessage.Marshal(nil)
	if err != nil {
		log.Error("Error marshalling packet", zap.String("ip_address", ip.String()), zap.Error(err))
		return
	}

	receiveBuffer := make([]byte, 1500) //nolint:gomnd
	if err := socket.SetReadDeadline(deadline); err != nil {
		log.Error("Error setting socket deadline", zap.String("ip_address", ip.String()), zap.Error(err))
		return
	}
	for {
		nBytes, peer, err := socket.ReadFrom(receiveBuffer)
		if err != nil {
			var nerr net.Error
			if errors.As(err, &nerr) {
				if nerr.Timeout() {
					log.Info("Timeout reading from socket",
						zap.String("ip_address", ip.String()), zap.Error(err))
					return
				}
			}
			log.Error("Error reading from socket for", zap.String("ip_address", ip.String()), zap.Error(err))
			continue
		}
		if peer.String() != ip.String() {
			continue
		}
		if bytes.Equal(receiveBuffer[:nBytes], icmpMessageBytes) {
			success = true
			latency = time.Since(sendTime)
			return
		}
	}
}
