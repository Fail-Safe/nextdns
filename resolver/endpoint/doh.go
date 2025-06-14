package endpoint

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
)

type ClientInfo struct {
	ID    string
	IP    string
	Model string
	Name  string
}

// Endpoint represents a DoH  server endpoint.
type DOHEndpoint struct {
	// Hostname use to contact the DoH server. If Bootstrap is provided,
	// Hostname is only used for TLS verification.
	Hostname string

	// Path to use with DoH HTTP requests. If empty, the path received in the
	// request by Transport is left untouched.
	Path string

	// Bootstrap is the IPs to use to contact the DoH server. When provided, no
	// DNS request is necessary to contact the DoH server. The fastest IP is
	// used.
	Bootstrap []string `json:"ips"`

	// ALPN is the list of alpn-id declared to be supported by the endpoint
	// through HTTPSSVC or Alt-Svc. If missing, h2 is assumed.
	ALPN []string

	// DoH3Supported caches whether this endpoint supports DoH3 (HTTP/3).
	DoH3Supported bool

	// FastestIP is the currently preferred IP for this endpoint, based on latency probing.
	FastestIP string

	once      sync.Once
	transport http.RoundTripper
	onConnect func(*ConnectInfo)
}

func (e *DOHEndpoint) Protocol() Protocol {
	return ProtocolDOH
}

func (e *DOHEndpoint) Equal(e2 Endpoint) bool {
	if e2, ok := e2.(*DOHEndpoint); ok {
		if e.Hostname != e2.Hostname || e.Path != e2.Path || len(e.Bootstrap) != len(e2.Bootstrap) {
			return false
		}
		for i := range e.Bootstrap {
			if e.Bootstrap[i] != e2.Bootstrap[i] {
				return false
			}
		}
		return true
	}
	return false
}

func (e *DOHEndpoint) String() string {
	if len(e.Bootstrap) != 0 {
		return fmt.Sprintf("https://%s%s#%s", e.Hostname, e.Path, strings.Join(e.Bootstrap, ","))
	}
	return fmt.Sprintf("https://%s%s", e.Hostname, e.Path)
}

func (e *DOHEndpoint) Exchange(ctx context.Context, payload, buf []byte) (n int, err error) {
	req, _ := http.NewRequest("POST", "https://nowhere"+e.Path, bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/dns-message")
	req = req.WithContext(ctx)
	res, err := e.RoundTrip(req)
	if err != nil {
		var uaeErr x509.UnknownAuthorityError
		if errors.As(err, &uaeErr) {
			return 0, fmt.Errorf("roundtrip: %v (subject=%v, issuer=%v)",
				err, uaeErr.Cert.Subject, uaeErr.Cert.Issuer)
		}
		return 0, fmt.Errorf("roundtrip: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("status: %d", res.StatusCode)
	}
	n, err = res.Body.Read(buf)
	if err != nil && !errors.Is(err, io.EOF) {
		return n, fmt.Errorf("read: %v", err)
	}
	return n, nil
}

func (e *DOHEndpoint) RoundTrip(req *http.Request) (resp *http.Response, err error) {
	e.once.Do(func() {
		if e.transport == nil {
			addrs := endpointAddrs(e)
			if e.DoH3Supported {
				// If using NextDNS and HTTP/3, rewrite hostname to doh3.dns.nextdns.io
				if strings.EqualFold(e.Hostname, "dns.nextdns.io") {
					e.Hostname = "doh3.dns.nextdns.io"
				}
				e.transport = newTransportH3(e, addrs)
			} else {
				e.transport = newTransportH2(e, addrs)
			}
		}
	})
	return e.transport.RoundTrip(req)
}

// endpointAddrs returns the list of addresses for a DOHEndpoint, prioritizing FastestIP if set.
// This version ensures FastestIP is first, with port, and all others follow (with port).
func endpointAddrs(e *DOHEndpoint) []string {
	addrs := make([]string, 0, len(e.Bootstrap))
	for _, ip := range e.Bootstrap {
		if !strings.Contains(ip, ":") {
			ip = net.JoinHostPort(ip, "443")
		}
		addrs = append(addrs, ip)
	}
	if e.FastestIP != "" {
		fastest := e.FastestIP
		if !strings.Contains(fastest, ":") {
			fastest = net.JoinHostPort(fastest, "443")
		}
		filtered := make([]string, 0, len(addrs))
		for _, a := range addrs {
			if a != fastest {
				filtered = append(filtered, a)
			}
		}
		addrs = append([]string{fastest}, filtered...)
	}
	return addrs
}
