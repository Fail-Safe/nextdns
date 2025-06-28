package endpoint

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/nextdns/nextdns/internal/dnsmessage"
)

type Protocol int

func (p Protocol) String() string {
	switch p {
	case ProtocolDOH:
		return "doh"
	case ProtocolDNS:
		return "dns"
	default:
		return "unknown"
	}
}

const (
	ProtocolDOH Protocol = iota
	ProtocolDNS
)

// Endpoint represents a DNS server endpoint.
type Endpoint interface {
	fmt.Stringer

	// Protocol returns the protocol used by this endpoint to transport DNS.
	Protocol() Protocol

	// Equal returns true if e represent the same endpoint.
	Equal(e Endpoint) bool

	// Send a DNS payload and get the response in buf.
	Exchange(ctx context.Context, payload, buf []byte) (n int, err error)
}

// New is a convenient method to build a Endpoint.
//
// Supported format for server are:
//
//   - DoH:   https://doh.server.com/path
//   - DoH:   https://doh.server.com/path#1.2.3.4 // with bootstrap
//   - DNS53: 1.2.3.4
//   - DNS53: 1.2.3.4:5353
func New(server string) (Endpoint, error) {
	if strings.HasPrefix(server, "https://") {
		u, err := url.Parse(server)
		if err != nil {
			return nil, err
		}
		e := &DOHEndpoint{
			Hostname: u.Host,
			Path:     u.Path,
		}
		if u.Fragment != "" {
			ips := strings.Split(u.Fragment, ",")
			e.Bootstrap = append([]string{}, ips...)
			e.AllBootstrap = append([]string{}, ips...)
		}
		return e, nil
	}

	host, port, err := net.SplitHostPort(server)
	if err != nil {
		host = server
		port = "53"
	}
	if ip := net.ParseIP(host); ip == nil {
		return nil, errors.New("not a valid IP address")
	}
	return &DNSEndpoint{
		Addr: net.JoinHostPort(host, port),
	}, nil
}

func endpointTester(e Endpoint) func(ctx context.Context, testDomain string) error {
	return func(ctx context.Context, testDomain string) error {
		payload := make([]byte, 0, 514)
		b := dnsmessage.NewBuilder(payload, dnsmessage.Header{
			RecursionDesired: true,
		})
		err := b.StartQuestions()
		if err != nil {
			return fmt.Errorf("start question: %v", err)
		}
		err = b.Question(dnsmessage.Question{
			Class: dnsmessage.ClassINET,
			Type:  dnsmessage.TypeA,
			Name:  dnsmessage.MustNewName(testDomain),
		})
		if err != nil {
			return fmt.Errorf("question: %v", err)
		}
		payload, err = b.Finish()
		if err != nil {
			return fmt.Errorf("finish: %v", err)
		}
		_, err = e.Exchange(ctx, payload, payload[:514])
		return err
	}
}

// MustNew is like New but panics on error.
func MustNew(server string) Endpoint {
	e, err := New(server)
	if err != nil {
		panic(err.Error())
	}
	return e
}

// Provider is a type responsible for producing a list of Endpoint.
type Provider interface {
	fmt.Stringer
	GetEndpoints(ctx context.Context) ([]Endpoint, error)
}

type ProviderFunc func(ctx context.Context) ([]Endpoint, error)

func (p ProviderFunc) String() string {
	return "ProviderFunc"
}

func (p ProviderFunc) GetEndpoints(ctx context.Context) ([]Endpoint, error) {
	return p(ctx)
}

// StaticProvider wraps a Endpoint slice to adapt it to the Provider interface.
type StaticProvider []Endpoint

func (p StaticProvider) String() string {
	es := make([]string, 0, len(p))
	for _, e := range p {
		es = append(es, e.String())
	}
	return fmt.Sprintf("StaticProvider(%v)", es)
}

// GetEndpoints implements the Provider interface.
func (p StaticProvider) GetEndpoints(ctx context.Context) ([]Endpoint, error) {
	return p, nil
}

// SourceURLProvider loads a list of endpoints from a remote URL.
type SourceURLProvider struct {
	// SourceURL is a URL pointing to a JSON resource listing one or more
	// Endpoints.
	SourceURL string

	// Client is the http.Client to use to fetch SourceURL. If not defined,
	// http.DefaultClient is used.
	Client *http.Client

	mu            sync.Mutex
	prevEndpoints []Endpoint
}

func (p *SourceURLProvider) String() string {
	return fmt.Sprintf("SourceURLProvider(%s)", p.SourceURL)
}

// GetEndpoints implements the Provider interface.
func (p *SourceURLProvider) GetEndpoints(ctx context.Context) ([]Endpoint, error) {
	c := p.Client
	if c == nil {
		c = http.DefaultClient
	}
	req, err := http.NewRequest("GET", p.SourceURL, nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	var dohEndpoints []*DOHEndpoint
	dec := json.NewDecoder(res.Body)
	err = dec.Decode(&dohEndpoints)
	if err != nil {
		return nil, err
	}
	endpoints := make([]Endpoint, len(dohEndpoints))
	for i := range dohEndpoints {
		endpoints[i] = dohEndpoints[i]
	}
	// Reuse previous endpoints when identical so we keep our conn pools warm.
	p.mu.Lock()
	defer p.mu.Unlock()
	for i, e := range endpoints {
		for _, pe := range p.prevEndpoints {
			if e.Equal(pe) {
				endpoints[i] = pe
			}
		}
	}
	p.prevEndpoints = endpoints
	return endpoints, nil
}

type SourceHTTPSSVCProvider struct {
	Hostname string
	Source   Endpoint

	mu            sync.Mutex
	prevEndpoints []Endpoint
}

func (p *SourceHTTPSSVCProvider) String() string {
	return fmt.Sprintf("SourceHTTPSSVCProvider(%s, %s)", p.Hostname, p.Source)
}

// GetEndpoints implements the Provider interface.
func (p *SourceHTTPSSVCProvider) GetEndpoints(ctx context.Context) ([]Endpoint, error) {
	payload := make([]byte, 0, 1220)
	b := dnsmessage.NewBuilder(payload, dnsmessage.Header{
		RecursionDesired: true,
	})
	err := b.StartQuestions()
	if err != nil {
		return nil, fmt.Errorf("start question: %v", err)
	}
	err = b.Question(dnsmessage.Question{
		Class: dnsmessage.ClassINET,
		Type:  dnsmessage.TypeHTTPS,
		Name:  dnsmessage.MustNewName(fqdn(p.Hostname)),
	})
	if err != nil {
		return nil, fmt.Errorf("question: %v", err)
	}
	payload, err = b.Finish()
	if err != nil {
		return nil, fmt.Errorf("finish: %v", err)
	}
	n, err := p.Source.Exchange(ctx, payload, payload[:1220])
	if err != nil {
		return nil, fmt.Errorf("exchange: %v", err)
	}

	var pr dnsmessage.Parser
	if _, err := pr.Start(payload[:n]); err != nil {
		return nil, err
	}
	if err := pr.SkipAllQuestions(); err != nil {
		return nil, fmt.Errorf("SkipAllQuestions: %w", err)
	}
	var endpoints []Endpoint
	var prio uint16
	var e *DOHEndpoint
	for {
		rh, err := pr.AnswerHeader()
		if err != nil {
			if !errors.Is(err, dnsmessage.ErrSectionDone) {
				return nil, fmt.Errorf("AnswerHeader: %w", err)
			}
			break
		}
		switch rh.Type {
		case dnsmessage.TypeHTTPS:
			rr, err := pr.HTTPSResource()
			if err != nil {
				return nil, fmt.Errorf("HTTPSResource: %w", err)
			}
			if prio < rr.Priority && e != nil {
				// Priority change, treat it as a fallback endpoint.
				endpoints = append(endpoints, e)
				e = nil
			}
			prio = rr.Priority
			if e == nil {
				e = &DOHEndpoint{Hostname: p.Hostname}
			}
			for _, p := range rr.Params {
				switch p.Key {
				case dnsmessage.ParamIPv4Hint:
					e.Bootstrap, err = appendIPHint(e.Bootstrap, p.Value, 4)
				case dnsmessage.ParamIPv6Hint:
					e.Bootstrap, err = appendIPHint(e.Bootstrap, p.Value, 16)
				case dnsmessage.ParamALPN:
					e.ALPN, err = parseAlpn(p.Value)
				default:
					continue
				}
				if err != nil {
					return nil, err
				}
			}
		default:
			_ = pr.SkipAnswer()
		}
	}
	if e != nil {
		e.AllBootstrap = append([]string{}, e.Bootstrap...)
		endpoints = append(endpoints, e)
	}

	// Caching logic: reuse previous endpoints if they are Equal, else update
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.prevEndpoints) == len(endpoints) {
		for i := range endpoints {
			// Try to find a previous endpoint with the same Hostname/Path (even if Bootstrap changed)
			if prev, ok := p.prevEndpoints[i].(*DOHEndpoint); ok {
				if curr, ok2 := endpoints[i].(*DOHEndpoint); ok2 && prev.Hostname == curr.Hostname && prev.Path == curr.Path {
					// Always update Bootstrap/AllBootstrap to match the previous object (which may have been updated by the monitor)
					curr.mu.Lock()
					prev.mu.Lock()
					curr.Bootstrap = append([]string{}, prev.Bootstrap...)
					curr.AllBootstrap = append([]string{}, prev.AllBootstrap...)
					prev.mu.Unlock()
					curr.mu.Unlock()
					endpoints[i] = prev
					continue
				}
			}
			// Fallback: if still Equal, reuse previous object
			if endpoints[i].Equal(p.prevEndpoints[i]) {
				endpoints[i] = p.prevEndpoints[i]
			}
		}
	}
	p.prevEndpoints = endpoints
	return endpoints, nil
}

func fqdn(s string) string {
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}

func appendIPHint(hints []string, hint []byte, ipSize int) ([]string, error) {
	for len(hint) >= ipSize {
		hints = append(hints, net.IP(hint[:ipSize]).String())
		hint = hint[ipSize:]
	}
	if len(hint) != 0 {
		return nil, errors.New("IP hint not aligned")
	}
	return hints, nil
}

func parseAlpn(b []byte) ([]string, error) {
	alpn := make([]string, 0, len(b)/4)
	for off := 0; off < len(b); {
		l := int(b[off])
		off++
		if off+l > len(b) {
			return nil, errors.New("alpn array overflowing")
		}
		alpn = append(alpn, string(b[off:off+l]))
		off += l
	}
	return alpn, nil
}

// StartDoHLatencyMonitor runs a goroutine that every 5 minutes finds the single fastest IP across all DOHEndpoints and sets it as preferred for all.
// This function is always non-blocking and safe for production use.
func StartDoHLatencyMonitor(ctx context.Context, endpoints []*DOHEndpoint, testDomain string, numQueries int) {
	go func() {
		defer func() {
			if r := recover(); r != nil {
				fmt.Printf("[DoHLatency] Latency monitor panicked: %v\n", r)
			}
		}()
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			fmt.Printf("[DoHLatency] Starting new latency monitoring round at %s\n", time.Now().Format(time.RFC3339))

			type result struct {
				endpointIdx int
				endpoint    *DOHEndpoint
				fastestIP   string
				fastestAvg  float64
			}
			resultsCh := make(chan result, len(endpoints))
			var wg sync.WaitGroup

			for i, e := range endpoints {
				wg.Add(1)
				go func(i int, e *DOHEndpoint) {
					defer wg.Done()
					fmt.Printf("[DoHLatency] Checking endpoint %d/%d: %s\n", i+1, len(endpoints), e.Hostname)
					e.mu.Lock()
					ips := append([]string{}, e.AllBootstrap...)
					e.mu.Unlock()
					if len(ips) == 0 {
						resultsCh <- result{i, e, "", math.MaxFloat64}
						return
					}
					fastestIP := ""
					fastestAvg := math.MaxFloat64
					for _, ip := range ips {
						var total float64
						var count int
						for i := 0; i < numQueries; i++ {
							ctxQ, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
							start := time.Now()
							clone := &DOHEndpoint{
								Hostname:  e.Hostname,
								Path:      e.Path,
								ALPN:      e.ALPN,
								Bootstrap: []string{ip},
							}
							buf := make([]byte, 1500)
							payload := make([]byte, 0, 514)
							b := dnsmessage.NewBuilder(payload, dnsmessage.Header{RecursionDesired: true})
							if err := b.StartQuestions(); err != nil {
								cancel()
								continue
							}
							if err := b.Question(dnsmessage.Question{Class: dnsmessage.ClassINET, Type: dnsmessage.TypeA, Name: dnsmessage.MustNewName(testDomain)}); err != nil {
								cancel()
								continue
							}
							payload, err := b.Finish()
							if err != nil {
								cancel()
								continue
							}
							_, err = clone.Exchange(ctxQ, payload, buf)
							cancel()
							if err != nil {
								continue
							}
							total += float64(time.Since(start).Milliseconds())
							count++
							if i < numQueries-1 {
								time.Sleep(1000 * time.Millisecond)
							}
						}
						if count == 0 {
							continue
						}
						avg := total / float64(count)
						fmt.Printf("[DoHLatency] %s: IP %s avg %.2fms over %d queries\n", e.Hostname, ip, avg, count)
						if avg < fastestAvg {
							fastestAvg = avg
							fastestIP = ip
						}
					}
					resultsCh <- result{i, e, fastestIP, fastestAvg}
				}(i, e)
			}

			wg.Wait()
			close(resultsCh)

			globalFastestIP := ""
			globalFastestAvg := math.MaxFloat64
			globalFastestHost := ""
			for res := range resultsCh {
				if res.fastestIP != "" && res.fastestAvg < globalFastestAvg {
					globalFastestIP = res.fastestIP
					globalFastestAvg = res.fastestAvg
					globalFastestHost = res.endpoint.Hostname
				}
			}

			fmt.Printf("[DoHLatency] Global fastest IP: %s (%.2fms, from %s)\n", globalFastestIP, globalFastestAvg, globalFastestHost)
			if globalFastestIP != "" {
				for _, e := range endpoints {
					var needSwitch bool
					e.mu.Lock()
					if len(e.Bootstrap) == 0 || e.Bootstrap[0] != globalFastestIP {
						e.Bootstrap = []string{globalFastestIP}
						needSwitch = true
					}
					e.mu.Unlock()
					if needSwitch {
						e.CloseIdleConnections()
						e.ResetTransport()
						fmt.Printf("[DoHLatency] %s: switched to global fastest IP %s (avg %.2fms, from %s)\n", e.Hostname, globalFastestIP, globalFastestAvg, globalFastestHost)
						if e.manager != nil {
							go func(m *Manager) {
								ctx2, cancel := context.WithTimeout(context.Background(), 2*time.Second)
								defer cancel()
								m.Test(ctx2)
							}(e.manager)
						}
					}
				}
			} else {
				fmt.Printf("[DoHLatency] No working bootstrap IPs found across all endpoints.\n")
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}
