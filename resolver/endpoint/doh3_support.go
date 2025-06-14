package endpoint

import (
	"context"
	"crypto/tls"
	"log"
	"net"
	"net/http"
	"time"

	quic "github.com/quic-go/quic-go"
)

// SupportsDoH3 returns true if DoH3 (HTTP/3) is supported for the given endpoint and bootstrap IPs.
// This version always attempts a real DoH3 request, regardless of ALPN.
func SupportsDoH3(endpoint string, bootstrapIPs []string, alpnList []string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := probeDoH3(ctx, endpoint, bootstrapIPs); err == nil {
		return true
	}
	log.Printf("[DoH3] QUIC probe failed for endpoint=%s, trying real DoH3 request", endpoint)
	if err := probeDoH3Request(ctx, endpoint, bootstrapIPs); err == nil {
		return true
	}
	return false
}

// alpnIncludesH3 checks if the ALPN string (comma-separated, e.g. "h3,h2") contains "h3".
// This matches the format seen in SVCB/HTTPS records.
// func alpnIncludesH3(alpn string) bool {
// 	for _, proto := range strings.Split(alpn, ",") {
// 		if strings.TrimSpace(proto) == "h3" {
// 			return true
// 		}
// 	}
// 	return false
// }

// probeDoH3 tries to establish a QUIC connection to the endpoint using all bootstrap IPs.
func probeDoH3(ctx context.Context, endpoint string, bootstrapIPs []string) error {
	if len(bootstrapIPs) == 0 {
		log.Printf("[DoH3] No bootstrap IPs for endpoint=%s", endpoint)
		return context.DeadlineExceeded
	}
	var lastErr error
	for _, ip := range bootstrapIPs {
		addr := net.JoinHostPort(ip, "443")
		log.Printf("[DoH3] Probing QUIC to %s (SNI=%s)", addr, endpoint)
		tlsConf := &tls.Config{
			ServerName: endpoint,
			NextProtos: []string{"h3"}, // Ensure ALPN "h3" is offered for probe
		}
		_, err := quic.DialAddrEarly(ctx, addr, tlsConf, nil)
		if err == nil {
			log.Printf("[DoH3] QUIC probe to %s succeeded", addr)
			return nil // success
		}
		log.Printf("[DoH3] QUIC probe to %s failed: %v", addr, err)
		lastErr = err
	}
	return lastErr
}

// probeDoH3Request attempts a real DoH3 DNS request using HTTP/3 to confirm support.
func probeDoH3Request(ctx context.Context, endpoint string, bootstrapIPs []string) error {
	if len(bootstrapIPs) == 0 {
		return context.DeadlineExceeded
	}
	for _, ip := range bootstrapIPs {
		url := "https://" + endpoint + "/dns-query"
		tr := newTransportH3(&DOHEndpoint{Hostname: endpoint}, []string{ip})
		req, _ := http.NewRequestWithContext(ctx, "POST", url, nil)
		req.Header.Set("Content-Type", "application/dns-message")
		resp, err := tr.RoundTrip(req)
		if err == nil && resp.StatusCode == 200 {
			resp.Body.Close()
			return nil
		}
		if resp != nil {
			resp.Body.Close()
		}
	}
	return context.DeadlineExceeded
}
