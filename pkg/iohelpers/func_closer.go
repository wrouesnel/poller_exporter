package iohelpers

import "io"

type funcCloser struct {
	io.Reader
	closer func() error
}

func (f funcCloser) Close() error {
	return f.closer()
}

// FuncCloser turns an io.Reader into an io.ReadCloser by calling
// a supplied function on Close.
func FuncCloser(r io.Reader, closer func() error) io.ReadCloser {
	return funcCloser{
		Reader: r,
		closer: closer,
	}
}
