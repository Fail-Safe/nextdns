package endpoint

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"runtime"
	"sync/atomic"
	"time"
)

type transport struct {
	http.RoundTripper
	hostname string
	path     string
	addr     string
}

var (
	connCount int64
)

func newTransportH2(e *DOHEndpoint, addrs []string) http.RoundTripper {
	d := &parallelDialer{}
	d.FallbackDelay = -1 // disable happy eyeball, we do our own
	var t http.RoundTripper = &http.Transport{
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second, // or your preferred value
		TLSClientConfig: &tls.Config{
			ServerName:         e.Hostname,
			RootCAs:            getRootCAs(),
			ClientSessionCache: tls.NewLRUClientSessionCache(0),
		},
		DialContext: func(ctx context.Context, network, _ string) (c net.Conn, err error) {
			atomic.AddInt64(&connCount, 1)
			if Log != nil && atomic.LoadInt64(&connCount)%100 == 0 {
				Log.Debugf("[DoHTransport] Total new connections: %d", atomic.LoadInt64(&connCount))
			}
			c, err = d.DialParallel(ctx, network, addrs)
			if c != nil {
				// Try to workaround the bug describe in this issue:
				// https://github.com/golang/go/issues/23559
				//
				// All write operations are surrounded with a 5s deadline that
				// will close the h2 connection if reached. This is not a proper
				// fix but an attempt to mitigate the issue waiting for an
				// upstream fix.
				//
				// See #196 for more info.
				c = deadlineConn{
					Conn:    c,
					timeout: 5 * time.Second,
				}
			}
			return c, err
		},
		ForceAttemptHTTP2: true,
	}
	runtime.SetFinalizer(t, func(t *http.Transport) {
		t.CloseIdleConnections()
	})
	if e.onConnect != nil {
		t = roundTripperConnectTracer{
			RoundTripper: t,
			OnConnect:    e.onConnect,
		}
	}
	return t
}

func (t transport) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Host = t.addr
	req.Host = t.hostname
	if t.path != "" {
		req.URL.Path = t.path
	}
	return t.RoundTripper.RoundTrip(req)
}

func endpointAddrs(e *DOHEndpoint) (addrs []string) {
	// Always use only the first Bootstrap IP if available
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.Bootstrap) != 0 {
		addrs = []string{net.JoinHostPort(e.Bootstrap[0], "443")}
	} else {
		addrs = []string{net.JoinHostPort(e.Hostname, "443")}
	}
	return addrs
}
