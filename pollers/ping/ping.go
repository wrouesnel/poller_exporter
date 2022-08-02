package ping

import (
	"bytes"
	"go.uber.org/zap"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"net"
	"os"
	"sync"
	"time"
)

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
	icmpSequence += 1
	return icmpSequence
}

// Sends a single ICMP echo to an IP and returns success and latency information.
// Borrowed from BrianBrazil's blackbox exporter
func Ping(ip net.IP, maxRTT time.Duration) (success bool, latency time.Duration) {
	log := zap.L()
	deadline := time.Now().Add(maxRTT)

	var socket *icmp.PacketConn
	var err error
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
	pid := os.Getpid() & 0xffff

	// Build the packet
	var wm icmp.Message
	if isIPv4(ip) {
		wm = icmp.Message{
			Type: ipv4.ICMPTypeEcho, Code: 0,
			Body: &icmp.Echo{
				ID: pid, Seq: int(seq),
				Data: []byte("poller_exporter"),
			},
		}
	} else if isIPv6(ip) {
		wm = icmp.Message{
			Type: ipv6.ICMPTypeEchoRequest, Code: 0,
			Body: &icmp.Echo{
				ID: pid, Seq: int(seq),
				Data: []byte("poller_exporter"),
			},
		}
	} else {
		log.Error("IP did not match any known types?")
		return
	}

	wb, err := wm.Marshal(nil)
	if err != nil {
		log.Error("Error marshalling packet", zap.String("ip_address", ip.String()), zap.Error(err))
		return
	}

	sendTime := time.Now()

	var dst *net.IPAddr
	dst = &net.IPAddr{IP: ip}

	if _, err := socket.WriteTo(wb, dst); err != nil {
		log.Error("Error writing to socket", zap.String("ip_address", ip.String()), zap.Error(err))
		return
	}

	// Reply should be the same except for the message type.
	if isIPv4(ip) {
		wm.Type = ipv4.ICMPTypeEchoReply
	} else if isIPv6(ip) {
		wm.Type = ipv6.ICMPTypeEchoReply
	} else {
		log.Error("IP did not match any known types?")
		return
	}

	wb, err = wm.Marshal(nil)
	if err != nil {
		log.Error("Error marshalling packet", zap.String("ip_address", ip.String()), zap.Error(err))
		return
	}

	rb := make([]byte, 1500)
	if err := socket.SetReadDeadline(deadline); err != nil {
		log.Error("Error setting socket deadline", zap.String("ip_address", ip.String()), zap.Error(err))
		return
	}
	for {
		n, peer, err := socket.ReadFrom(rb)
		if err != nil {
			if nerr, ok := err.(net.Error); ok && nerr.Timeout() {
				log.Info("Timeout reading from socket", zap.String("ip_address", ip.String()), zap.Error(err))
				return
			}
			log.Error("Error reading from socket for", zap.String("ip_address", ip.String()), zap.Error(err))
			continue
		}
		if peer.String() != ip.String() {
			continue
		}
		if bytes.Compare(rb[:n], wb) == 0 {
			success = true
			latency = time.Now().Sub(sendTime)
			return
		}
	}
}
