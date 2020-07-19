package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	_ "net/http/pprof" // nolint:gosec
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/matrix-org/gomatrixserverlib"

	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	fetchKeysTimeout = 10 * time.Second
)

// HandleReport handles an HTTP request for a JSON report for matrix server.
// GET /api/report?server_name=matrix.org request.
func HandleReport(w http.ResponseWriter, req *http.Request) {
	// Set unrestricted Access-Control headers so that this API can be used by
	// web apps running in browsers.
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept")
	if req.Method == "OPTIONS" {
		return
	}
	if req.Method != "GET" {
		w.WriteHeader(405)
		handleRequestError(w, "Unsupported method")
		return
	}
	serverName := gomatrixserverlib.ServerName(req.URL.Query().Get("server_name"))
	if len(serverName) == 0 {
		w.WriteHeader(400)
		handleRequestError(w, "Missing server_name parameter")
		return
	}

	result, err := JSONReport(serverName)
	if err != nil {
		w.WriteHeader(500)
		handleRequestError(w, fmt.Sprintf("Error generating report: %s\n", err.Error()))
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		if _, err = w.Write(result); err != nil {
			fmt.Printf("Error generating report: %q\n", err.Error())
		}
	}
}

// handleRequestError prints an error message to the standard output then tries
// to write it to a http.ResponseWriter.
// If writing failed, prints a message containing the error that came up then to
// the standard output.
func handleRequestError(w http.ResponseWriter, errMsg string) {
	fmt.Printf("ERR: %s\n", errMsg)

	if _, err := w.Write([]byte(errMsg)); err != nil {
		fmt.Printf("Error sending error to client: %s\n", err.Error())
	}
}

// JSONReport generates a JSON formatted report for a matrix server.
func JSONReport(
	serverName gomatrixserverlib.ServerName,
) ([]byte, error) {
	results, err := Report(serverName)
	if err != nil {
		return nil, err
	}
	results.touchUpReport()
	encoded, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	if err = json.Indent(&buffer, encoded, "", "  "); err != nil {
		fmt.Printf("Error Generating Report: %q\n", err.Error())
	}
	return buffer.Bytes(), nil
}

func main() {
	http.HandleFunc("/api/report", prometheus.InstrumentHandlerFunc("report", HandleReport))
	http.Handle("/metrics", prometheus.Handler())
	// ListenAndServe always returns a non-nil error so we want to panic here.
	panic(http.ListenAndServe(os.Getenv("BIND_ADDRESS"), nil))
}

// A ServerReport is a report for a matrix server.
type ServerReport struct {
	Error             string                      `json:",omitempty"` // Error which happened before connecting to the server.
	WellKnownResult   WellKnownReport             // The result of looking up the server's .well-known/matrix/server file.
	DNSResult         DNSResult                   // The result of looking up the server in DNS.
	ConnectionReports map[string]ConnectionReport // The report for each server address we could connect to.
	ConnectionErrors  map[string]error            // The errors for each server address we couldn't connect to.
	Version           VersionReport               // The version information for the server
	FederationOK      bool                        // Summary about whether the run didn't encounter anything that could hamper federation.
}

// A VersionReport is a combination of data from matrix server's version
// information, as well as any errors reported during the lookup.
type VersionReport struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Error   string `json:"error,omitempty"`
}

// A WellKnownReport is the combination of data from a matrix server's
// .well-known file, as well as any errors reported during the lookup.
type WellKnownReport struct {
	ServerAddress gomatrixserverlib.ServerName `json:"m.server"`
	Result        string                       `json:"result,omitempty"`
}

// A DNSResult is the result of looking up a matrix server in DNS.
type DNSResult struct {
	SRVCName   string                // The canonical name for the SRV record in DNS
	SRVRecords []*net.SRV            // List of SRV record for the matrix server.
	SRVError   error                 // If there was an error getting the SRV records.
	Hosts      map[string]HostResult // The results of looking up the SRV record targets.
	Addrs      []string              // List of "<ip>:<port>" strings that the server is listening on. These strings can be passed to `net.Dial()`.
}

// A HostResult is the result of looking up the IP addresses for a host.
type HostResult struct {
	CName string   // The canonical name for the host.
	Addrs []string // The IP addresses for the host.
	Error error    // If there was an error getting the IP addresses.
}

// Info is a struct that contains federation checks that are not necessary in
// order for proper federation. These are placed in a separate field in order to
// make parsing the resulting JSON simpler
type Info struct{}

// A ConnectionReport is information about a connection made to a matrix server.
type ConnectionReport struct {
	Certificates      []X509CertSummary                                          // Summary information for each x509 certificate served up by this server.
	Cipher            CipherSummary                                              // Summary information on the TLS cipher used by this server.
	Checks            ConnectionChecks                                           // Checks applied to the server and their results.
	Errors            []error                                                    // String slice describing any problems encountered during testing.
	Ed25519VerifyKeys map[gomatrixserverlib.KeyID]gomatrixserverlib.Base64String // The Verify keys for this server or nil if the checks were not ok.
	Info              Info                                                       // Checks that are not necessary to pass, rather simply informative.
	Keys              *json.RawMessage                                           // The server key JSON returned by this server.
}

// ConnectionChecks represents the result of the checks done on a connection
// made to a Matrix homeserver. It extends the gomatrixserverlib.KeyChecks
// structure.
type ConnectionChecks struct {
	gomatrixserverlib.KeyChecks      // Checks done by gomatrixserverlib from the keys exposed by the server.
	ValidCertificates           bool // The X509 certificates have been verified by the system root CAs.
}

// A CipherSummary is a summary of the TLS version and Cipher used in a TLS connection.
type CipherSummary struct {
	Version     string // Human readable description of the TLS version.
	CipherSuite string // Human readable description of the TLS cipher.
}

// A X509CertSummary is a summary of the information in a X509 certificate.
type X509CertSummary struct {
	SubjectCommonName string                         // The common name of the subject.
	IssuerCommonName  string                         // The common name of the issuer.
	SHA256Fingerprint gomatrixserverlib.Base64String // The SHA256 fingerprint of the certificate.
	DNSNames          []string                       // The DNS names this certificate is valid for.
}

// Report creates a ServerReport for a matrix server.
func Report(
	serverName gomatrixserverlib.ServerName,
) (report ServerReport, err error) {
	// Map of network address to report.
	report.ConnectionReports = make(map[string]ConnectionReport)

	// Map of network address to connection error.
	report.ConnectionErrors = make(map[string]error)

	// This would be set to false as soon as one check fails or an error is reported.
	// TODO: We probably should expect it to be false and only set it to true if everything
	// worked after checking.
	report.FederationOK = true

	// Host address of the server (can be different from the serverName through well-known)
	serverHost := serverName

	// Validate the server name, and retrieve domain name to send as SNI to server
	sni, _, valid := gomatrixserverlib.ParseAndValidateServerName(serverHost)
	if !valid {
		report.Error = fmt.Sprintf("Invalid server name '%s'", serverHost)
		return
	}

	// Check for .well-known
	var wellKnownResult *gomatrixserverlib.WellKnownResult
	if wellKnownResult, err = gomatrixserverlib.LookupWellKnown(serverName); err == nil {
		// Use well-known as new host
		serverHost = wellKnownResult.NewAddress
		report.WellKnownResult.ServerAddress = wellKnownResult.NewAddress

		// need to revalidate the server name and update the SNI
		sni, _, valid = gomatrixserverlib.ParseAndValidateServerName(serverHost)
		if !valid {
			report.Error = fmt.Sprintf("Invalid server name '%s' in .well-known result", serverHost)
			return
		}
	} else {
		report.WellKnownResult.Result = err.Error()
	}

	// Lookup server version
	client := gomatrixserverlib.NewClient()
	version, err := client.GetVersion(context.TODO(), serverHost)
	if err == nil {
		report.Version.Name = version.Server.Name
		report.Version.Version = version.Server.Version
	} else {
		report.Version.Error = err.Error()
	}

	dnsResult, err := lookupServer(serverHost)
	if err != nil {
		return
	}
	report.DNSResult = *dnsResult

	// Mark federation as not OK if no address could be found.
	if len(report.DNSResult.Addrs) == 0 {
		report.FederationOK = false
	}

	// Ensure only one thread updates the report at a time.
	mutex := new(sync.Mutex)
	wg := sync.WaitGroup{}
	// Iterate through each address and run checks in parallel
	for _, addr := range report.DNSResult.Addrs {
		wg.Add(1)
		go func(report *ServerReport, serverHost, serverName gomatrixserverlib.ServerName, addr, sni string) {
			defer wg.Done()

			if connReport, connErr := connCheck(
				addr, serverHost, serverName, sni,
			); connErr != nil {
				mutex.Lock()
				defer mutex.Unlock()
				report.FederationOK = false
				report.ConnectionErrors[addr] = connErr
			} else {
				mutex.Lock()
				defer mutex.Unlock()
				report.FederationOK = report.FederationOK && connReport.Checks.AllChecksOK
				report.ConnectionReports[addr] = *connReport
			}
		}(&report, serverHost, serverName, addr, sni)
	}
	// Wait for checks to finish
	wg.Wait()

	return
}

// lookupServer looks up a matrix server in DNS.
func lookupServer(serverName gomatrixserverlib.ServerName) (*DNSResult, error) { // nolint: gocyclo
	var result DNSResult
	result.Hosts = map[string]HostResult{}

	hosts := map[string][]net.SRV{}
	if !strings.Contains(string(serverName), ":") {
		// If there isn't an explicit port set then try to look up the SRV record.
		var err error
		result.SRVCName, result.SRVRecords, err = net.LookupSRV("matrix", "tcp", string(serverName))
		result.SRVError = err

		if err != nil {
			if dnserr, ok := err.(*net.DNSError); ok {
				// If the error is a network timeout talking to the DNS server
				// then give up now rather than trying to fallback.
				if dnserr.Timeout() {
					return nil, err
				}
			}
			// If there isn't a SRV record in DNS then fallback to "serverName:8448".
			hosts[string(serverName)] = []net.SRV{{
				Target: string(serverName),
				Port:   8448,
			}}
		} else {
			// Group the SRV records by target host.
			for _, record := range result.SRVRecords {
				// Check whether the target is a CNAME record.
				cname, err := net.LookupCNAME(record.Target)
				if err != nil {
					result.Hosts[record.Target] = HostResult{
						CName: cname,
						Error: err,
					}
					continue
				}
				// There is no straightforward way to know whether a the target
				// is an A record or a CNAME one. Therefore, we use the fact
				// that LookupCNAME returns the FQDN it was given if it can't
				// find a CNAME record to follow.
				if cname != record.Target {
					result.Hosts[record.Target] = HostResult{
						CName: cname,
						Error: fmt.Errorf("SRV record target %s is a CNAME record, which is forbidden (as per RFC2782)", record.Target),
					}
					continue
				}
				hosts[record.Target] = append(hosts[record.Target], *record)
			}
		}
	} else {
		// There is a explicit port set in the server name.
		// We don't need to look up any SRV records.
		host, portStr, err := net.SplitHostPort(string(serverName))
		if err != nil {
			return nil, err
		}
		var port uint64
		port, err = strconv.ParseUint(portStr, 10, 16)
		if err != nil {
			return nil, err
		}
		hosts[host] = []net.SRV{{
			Target: host,
			Port:   uint16(port),
		}}
	}

	// Look up the IP addresses for each host.
	for host, records := range hosts {
		// Ignore any DNS errors when looking up the CNAME. We only are interested in it for debugging.
		cname, err := net.LookupCNAME(host)
		if err != nil {
			continue
		}
		addrs, err := net.LookupHost(host)
		result.Hosts[host] = HostResult{
			CName: cname,
			Addrs: addrs,
			Error: err,
		}
		// For each SRV record, for each IP address add a "<ip>:<port>" entry to the list of addresses.
		for _, record := range records {
			for _, addr := range addrs {
				ipPort := net.JoinHostPort(addr, strconv.Itoa(int(record.Port)))
				result.Addrs = append(result.Addrs, ipPort)
			}
		}
	}

	return &result, nil
}

// connCheck generates a connection report for a given address.
// It's given the address to generate a report for, the server's host (which can
// differ from the server's name if .well-known delegation is in use, and can be
// either a single hostname or a hostname and a port), the server's name, the
// SNI to send to the server when talking to it (which is the hostname part of
// serverHost), and the result of a .well-known lookup.
// Returns an error if the keys for the server couldn't be fetched.
func connCheck(
	addr string, serverHost, serverName gomatrixserverlib.ServerName, sni string,
) (*ConnectionReport, error) {
	keys, connState, err := fetchKeysDirect(serverHost, addr, sni)
	if err != nil {
		return nil, err
	}
	var connReport = new(ConnectionReport)
	// Slice of human readable errors found during testing.
	connReport.Errors = make([]error, 0, 0)

	// Check for valid X509 certificate
	// We can assume connState.PeerCertificates[0] exists because tls returns an
	// error if the message contained 0 certificates, cf
	// https://golang.org/src/crypto/tls/handshake_client.go#L445
	leafCert := connState.PeerCertificates[0]
	intermediateCerts := x509.NewCertPool()
	for _, cert := range connState.PeerCertificates[1:] {
		intermediateCerts.AddCert(cert)
	}

	valid, err := gomatrixserverlib.IsValidCertificate(serverHost, leafCert, intermediateCerts)
	if err != nil {
		connReport.Errors = append(connReport.Errors, asReportError(err))
	}
	connReport.Checks.ValidCertificates = valid

	for _, cert := range connState.PeerCertificates {
		fingerprint := sha256.Sum256(cert.Raw)
		summary := X509CertSummary{
			SubjectCommonName: cert.Subject.CommonName,
			IssuerCommonName:  cert.Issuer.CommonName,
			SHA256Fingerprint: fingerprint[:],
			DNSNames:          cert.DNSNames,
		}
		connReport.Certificates = append(connReport.Certificates, summary)
	}
	connReport.Cipher.Version = enumToString(tlsVersions, connState.Version)
	connReport.Cipher.CipherSuite = enumToString(tlsCipherSuites, connState.CipherSuite)
	connReport.Checks.KeyChecks, connReport.Ed25519VerifyKeys = gomatrixserverlib.CheckKeys(serverName, time.Now(), *keys)
	// Certificate validity verification isn't done by CheckKeys so we need to
	// make sure AllChecksOK is false if it failed.
	connReport.Checks.AllChecksOK = connReport.Checks.AllChecksOK && connReport.Checks.ValidCertificates
	connReport.Info = infoChecks()
	raw := json.RawMessage(keys.Raw)
	connReport.Keys = &raw

	return connReport, nil
}

// fetchKeysDirect fetches the matrix keys for a given server name directly from
// the given address.
// Optionally sets a SNI header if ``sni`` is not empty.
// Note that this function doesn't check the validity of the certificate(s)
// served by the server.
// Returns an error if either sending the request or decoding the JSON response
// failed. The server responding with a non-200 response also causes an error to
// be returned.
// Returns the server keys and the state of the TLS connection used to retrieve
// them.
func fetchKeysDirect(
	serverName gomatrixserverlib.ServerName, addr, sni string,
) (*gomatrixserverlib.ServerKeys, *tls.ConnectionState, error) {
	cli := http.Client{
		Timeout: fetchKeysTimeout,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				ServerName: sni,
				// TODO: Remove this once Synapse 1.0 is out.
				InsecureSkipVerify: true, // nolint: gas, gosec
			},
		},
	}

	// Create a GET /_matrix/key/v2/server request.
	requestURL := "https://" + addr + "/_matrix/key/v2/server"
	request, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, nil, err
	}
	request.Host = string(serverName)
	request.Header.Set("Connection", "close")
	// Send the request and wait for the response.
	response, err := cli.Do(request)
	if err != nil {
		return nil, nil, err
	}
	if response != nil {
		defer response.Body.Close() // nolint: errcheck
	}
	if response.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("Non-200 response %d from remote server", response.StatusCode)
	}
	var keys gomatrixserverlib.ServerKeys
	if err = json.NewDecoder(response.Body).Decode(&keys); err != nil {
		return nil, nil, errors.Wrap(err, "Unable to decode JSON from remote server")
	}
	return &keys, response.TLS, nil
}

// infoChecks are checks that are not required for federation, just good-to-knows
func infoChecks() Info {
	return Info{}
}

// A ReportError is a version of a golang error that is human readable when serialised as JSON.
type ReportError struct {
	Message string // The result of err.Error()
}

// Error implements the error interface.
func (e ReportError) Error() string {
	return e.Message
}

// Replace a golang error with an error that is human readable when serialised as JSON.
func asReportError(err error) error {
	if err != nil {
		return ReportError{err.Error()}
	}
	return nil
}

// touchUpReport converts all the errors in a ServerReport into forms that will be human readable after JSON serialisation.
func (report *ServerReport) touchUpReport() {
	report.DNSResult.SRVError = asReportError(report.DNSResult.SRVError)
	for host, hostReport := range report.DNSResult.Hosts {
		hostReport.Error = asReportError(hostReport.Error)
		report.DNSResult.Hosts[host] = hostReport
	}
	for addr, err := range report.ConnectionErrors {
		report.ConnectionErrors[addr] = asReportError(err)
	}
}

// enumToString converts a uint16 enum into a human readable string using a fixed mapping.
// If no mapping can be found then return a "UNKNOWN[0x%x]" string with the raw enum.
func enumToString(names map[uint16]string, value uint16) string {
	if name, ok := names[value]; ok {
		return name
	}
	return fmt.Sprintf("UNKNOWN[0x%x]", value)
}

var (
	tlsVersions = map[uint16]string{
		tls.VersionSSL30: "SSL 3.0",
		tls.VersionTLS10: "TLS 1.0",
		tls.VersionTLS11: "TLS 1.1",
		tls.VersionTLS12: "TLS 1.2",
	}
	tlsCipherSuites = map[uint16]string{
		tls.TLS_RSA_WITH_RC4_128_SHA:                "TLS_RSA_WITH_RC4_128_SHA",
		tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA:           "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_RSA_WITH_AES_128_CBC_SHA:            "TLS_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_RSA_WITH_AES_256_CBC_SHA:            "TLS_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA:        "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:    "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA:          "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
		tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA:     "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:      "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:   "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:   "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
		// go1.5.3 doesn't have these enums, but they appear in more recent version.
		// tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         "TLS_RSA_WITH_AES_128_GCM_SHA256",
		// tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         "TLS_RSA_WITH_AES_256_GCM_SHA384",
	}
)
