// nolint:wrapcheck,nonamedreturns
package iohelpers

import (
	"net"
	"time"

	"go.uber.org/zap"
)

// LoggedConnection is a net.Conn helper which logs all call activity. It is
// useful for debugging packages with opaque connection handling paths, as
// poller_exporter leans heavily on incremental construction of net.Conn
// sessions.
type LoggedConnection struct {
	net.Conn
	l *zap.Logger
}

// NewTracedConnection wraps an existing connection to trace calls to methods
// on it.
func NewTracedConnection(conn net.Conn) net.Conn {
	return LoggedConnection{conn, zap.L()}
}

func (conn LoggedConnection) Read(b []byte) (n int, err error) {
	n, err = conn.Conn.Read(b)
	conn.l.Debug("Read", zap.Int("read_bytes", n), zap.Error(err))
	return
}

func (conn LoggedConnection) Write(b []byte) (n int, err error) {
	n, err = conn.Conn.Write(b)
	conn.l.Debug("Write", zap.Int("write_bytes", n), zap.Error(err))
	return
}

func (conn LoggedConnection) Close() error {
	err := conn.Conn.Close()
	conn.l.Debug("Close", zap.Error(err))
	return err
}

func (conn LoggedConnection) SetDeadline(t time.Time) error {
	err := conn.Conn.SetDeadline(t)
	conn.l.Debug("SetDeadline", zap.Time("deadline", t), zap.Error(err))
	return err
}

func (conn LoggedConnection) SetReadDeadline(t time.Time) error {
	err := conn.Conn.SetReadDeadline(t)
	conn.l.Debug("SetReadDeadline", zap.Time("read_deadline", t), zap.Error(err))
	return err
}

func (conn LoggedConnection) SetWriteDeadline(t time.Time) error {
	err := conn.Conn.SetWriteDeadline(t)
	conn.l.Debug("SetWriteDeadline", zap.Time("write_deadline", t), zap.Error(err))
	return err
}
