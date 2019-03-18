package gomatrixserverlib

import (
	"context"
	"fmt"
	"net"
	"reflect"
	"testing"

	"github.com/miekg/dns"
	"gopkg.in/h2non/gock.v1"
)

const (
	dnsPort = 5555
)

// assertCritical checks whether the second parameter it gets has the same type
// and value as the third one, and aborts the current test if that's not the
// case.
func assertCritical(t *testing.T, val, expected interface{}) {
	if !reflect.DeepEqual(val, expected) {
		fmt.Printf("expected %v to equal %v\n", val, expected)
		t.FailNow()
	}
}

// testResolve performs a server name resolution for a given server name and
// checks if the result matches with the given destination, Host header value
// and expected certificate name.
// If one of them doesn't match, or the resolution function returned with an
// error, it aborts the current test.
func testResolve(t *testing.T, serverName ServerName, destination, host, certName string) {
	res, err := ResolveServer(serverName)
	assertCritical(t, err, nil)
	assertCritical(t, len(res), 1)
	assertCritical(t, res[0].Destination, destination)
	assertCritical(t, res[0].Host, ServerName(host))
	assertCritical(t, res[0].TLSServerName, certName)
}

// Tests step 1 (IPv4 without a port) of the resolution algorithm.
func TestResolutionIPLiteral(t *testing.T) {
	testResolve(
		t,
		ServerName("42.42.42.42"), // The server name is an IP literal without a port
		"42.42.42.42:8448",        // Destination must be the IP address + port 8448
		"42.42.42.42",             // Host must be the IP address
		"42.42.42.42",             // Certificate (Name) must be for the IP address
	)
}

// Tests step 1 (IPv6 without a port) of the resolution algorithm.
func TestResolutionIPv6Literal(t *testing.T) {
	testResolve(
		t,
		ServerName("[42:42::42]"), // The server name is an IP literal without a port
		"[42:42::42]:8448",        // Destination must be the IP address + port 8448
		"[42:42::42]",             // Host must be the IP address
		"42:42::42",               // Certificate (Name) must be for the IP address
	)
}

// Tests step 1 (IPv4 with a port) of the resolution algorithm.
func TestResolutionIPLiteralWithPort(t *testing.T) {
	testResolve(
		t,
		ServerName("42.42.42.42:443"), // The server name is an IP literal with a port
		"42.42.42.42:443",             // Destination must be the IP address + port
		"42.42.42.42:443",             // Host must be the IP address + port
		"42.42.42.42",                 // Certificate (Name) must be for the IP address
	)
}

// Tests step 1 (IPv6 with a port) of the resolution algorithm.
func TestResolutionIPv6LiteralWithPort(t *testing.T) {
	testResolve(
		t,
		ServerName("[42:42::42]:443"), // The server name is an IP literal with a port
		"[42:42::42]:443",             // Destination must be the IP address + port
		"[42:42::42]:443",             // Host must be the IP address + port
		"42:42::42",                   // Certificate (Name) must be for the IP address
	)
}

// Tests step 2 of the resolution algorithm.
func TestResolutionHostnameAndPort(t *testing.T) {
	testResolve(
		t,
		ServerName("example.com:4242"), // The server name is not an IP literal and includes an explicit port
		"example.com:4242",             // Destination must be the hostname + port
		"example.com:4242",             // Host must be the hostname + port
		"example.com",                  // Certificate (Name) must be for the hostname
	)
}

// Tests step 3a (without a port) of the resolution algorithm.
func TestResolutionHostnameWellKnownWithIPLiteral(t *testing.T) {
	defer gock.Off()

	gock.New("https://example.com").
		Get("/.well-known/matrix/server").
		Reply(200).
		BodyString("{\"m.server\": \"42.42.42.42\"}")

	testResolve(
		t,
		ServerName("example.com"), // The server name is a domain hosting a .well-known file which specifies an IP literal without a port
		"42.42.42.42:8448",        // Destination must be the IP literal + port 8448
		"42.42.42.42",             // Host must be the IP literal
		"42.42.42.42",             // Certificate (Name) must be for the IP literal
	)
}

// Tests step 3a (with a port) of the resolution algorithm.
func TestResolutionHostnameWellKnownWithIPLiteralAndPort(t *testing.T) {
	defer gock.Off()

	gock.New("https://example.com").
		Get("/.well-known/matrix/server").
		Reply(200).
		BodyString("{\"m.server\": \"42.42.42.42:443\"}")

	testResolve(
		t,
		ServerName("example.com"), // The server name is a domain hosting a .well-known file which specifies an IP literal with a port
		"42.42.42.42:443",         // Destination must be the IP literal + port
		"42.42.42.42:443",         // Host must be the IP literal + port
		"42.42.42.42",             // Certificate (Name) must be for the IP literal
	)
}

// Tests step 3b of the resolution algorithm.
func TestResolutionHostnameWellKnownWithHostnameAndPort(t *testing.T) {
	defer gock.Off()

	gock.New("https://example.com").
		Get("/.well-known/matrix/server").
		Reply(200).
		BodyString("{\"m.server\": \"matrix.example.com:4242\"}")

	testResolve(
		t,
		ServerName("example.com"), // The server name is a domain hosting a .well-known file which specifies a hostname that's not an IP literal and has a port
		"matrix.example.com:4242", // Destination must be the hostname + port
		"matrix.example.com:4242", // Host must be the hostname + port
		"matrix.example.com",      // Certificate (Name) must be for the hostname
	)
}

// Tests step 3c of the resolution algorithm.
func TestResolutionHostnameWellKnownWithHostnameSRV(t *testing.T) {
	defer gock.Off()

	gock.New("https://example.com").
		Get("/.well-known/matrix/server").
		Reply(200).
		BodyString("{\"m.server\": \"matrix.example.com\"}")

	cleanup := setupFakeDNS(true)
	defer cleanup()

	testResolve(
		t,
		ServerName("example.com"),      // The server name is a domain hosting a .well-known file which specifies a hostname that's not an IP literal, has no port and for which a SRV record with a non-0 exists
		"matrix.otherexample.com:4242", // Destination must be the hostname + port from the SRV record
		"matrix.example.com",           // Host must be the delegated hostname
		"matrix.example.com",           // Certificate (Name) must be for the delegated hostname
	)
}

// Tests step 3d of the resolution algorithm.
func TestResolutionHostnameWellKnownWithHostnameNoSRV(t *testing.T) {
	defer gock.Off()

	gock.New("https://example.com").
		Get("/.well-known/matrix/server").
		Reply(200).
		BodyString("{\"m.server\": \"matrix.example.com\"}")

	cleanup := setupFakeDNS(false)
	defer cleanup()

	testResolve(
		t,
		ServerName("example.com"), // The server name is a domain hosting a .well-known file which specifies a hostname that's not an IP literal, has no port and for which no SRV record exists
		"matrix.example.com:8448", // Destination must be the delegated hostname + port 8448
		"matrix.example.com",      // Host must be the delegated hostname
		"matrix.example.com",      // Certificate (Name) must be for the delegated hostname
	)
}

// Tests step 4 of the resolution algorithm.
func TestResolutionHostnameWithSRV(t *testing.T) {
	cleanup := setupFakeDNS(true)
	defer cleanup()

	testResolve(
		t,
		ServerName("example.com"),      // The server name is a domain for which a SRV record exists with a non-0 port
		"matrix.otherexample.com:4242", // Destination must be the hostname + port
		"example.com",                  // Host must be the server name
		"example.com",                  // Certificate (Name) must be for the server name
	)
}

// Tests step 5 of the resolution algorithm.
func TestResolutionHostnameWithNoWellKnownNorSRV(t *testing.T) {
	defer gock.Off()

	gock.New("https://example.com").
		Get("/.well-known/matrix/server").
		Reply(404)

	cleanup := setupFakeDNS(false)
	defer cleanup()

	testResolve(
		t,
		ServerName("example.com"), // The server name is a domain for no .well-known file nor SRV record exist
		"example.com:8448",        // Destination must be the hostname + 8448
		"example.com",             // Host must be the server name
		"example.com",             // Certificate (Name) must be for the server name
	)
}

// setupFakeDNS starts a DNS server that mocks answers from a live DNS server
// for Matrix SRV lookups, and re-assigns the default DNS resolver so it only
// uses the local server. This is done to limit network calls over network we
// don't control in order to make tests more reliable and time-proof.
// It expects to be provided with a port to return in answers, and a boolean
// which, if set to false, will cause the server to respond to any query with no
// answer.
// Returns with a cleanup callback function to call when the fake DNS isn't
// needed anymore.
func setupFakeDNS(answerSRV bool) (cleanup func()) {
	defaultResolver := net.DefaultResolver

	// Start a DNS server with our custom handler.
	srv := &dns.Server{Addr: fmt.Sprintf("127.0.0.1:%d", dnsPort), Net: "udp"}
	srv.Handler = &dnsHandler{answerSRV: answerSRV}
	go func() {
		err := srv.ListenAndServe()
		if err != nil {
			panic(err)
		}
	}()

	// Redefine the default resolver so it uses our local server.
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			// Redirect every DNS query to our local server.
			return net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", dnsPort))
		},
	}

	// Define a function that will shutdown the DNS server, and reset the
	// default resolver with the value it had before being tempered with, so we
	// can return that as the callback function to call when the fake DNS isn't
	// needed anymore.
	cleanup = func() {
		srv.Shutdown()
		net.DefaultResolver = defaultResolver
	}

	return
}

// dnsHandler is the handler used to answer DNS queries.
type dnsHandler struct {
	answerSRV bool
}

// ServeDNS answers DNS queries.
func (h *dnsHandler) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	msg := dns.Msg{}
	msg.SetReply(r)
	switch r.Question[0].Qtype {
	case dns.TypeSRV:
		if h.answerSRV {
			msg.Authoritative = true
			domain := msg.Question[0].Name
			msg.Answer = append(msg.Answer, &dns.SRV{
				Hdr:      dns.RR_Header{Name: domain, Rrtype: dns.TypeSRV, Class: dns.ClassINET, Ttl: 60},
				Priority: 10,
				Weight:   0,
				Port:     4242,
				Target:   "matrix.otherexample.com.", // Domain name needs to be fully qualified.
			})
		}
	}

	err := w.WriteMsg(&msg)
	if err != nil {
		panic(err)
	}
}
