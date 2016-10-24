package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/matrix-org/golang-matrixfederation"
	"net/http"
	"os"
	"time"
)

func HandleReport(w http.ResponseWriter, req *http.Request) {
	serverName := req.URL.Query().Get("server_name")
	tlsSNI := req.URL.Query().Get("tls_sni")
	result, err := JSONReport(serverName, tlsSNI)
	if err != nil {
		w.WriteHeader(500)
		fmt.Printf("Error Generating Report: %q", err.Error())
	} else {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		w.Write(result)
	}
}

func JSONReport(serverName, sni string) ([]byte, error) {
	results, err := Report(serverName, sni)
	if err != nil {
		return nil, err
	}
	results.touchUpReport()
	encoded, err := json.Marshal(results)
	if err != nil {
		return nil, err
	}
	var buffer bytes.Buffer
	json.Indent(&buffer, encoded, "", "  ")
	return buffer.Bytes(), nil
}

func main() {
	http.HandleFunc("/report", HandleReport)
	http.ListenAndServe(os.Getenv("BIND_ADDRESS"), nil)
}

type ServerReport struct {
	DNSResult         matrixfederation.DNSResult
	ConnectionReports map[string]ConnectionReport
	ConnectionErrors  map[string]error
}

type ConnectionReport struct {
	Certificates []X509CertSummary
	Cipher       CipherSummary
	Keys         *json.RawMessage
	Checks       matrixfederation.KeyChecks
}

type CipherSummary struct {
	Version     string
	CipherSuite string
}

type X509CertSummary struct {
	SubjectCommonName string
	IssuerCommonName  string
	Sha256Fingerprint matrixfederation.Base64String
	DNSNames          []string
}

func Report(serverName string, sni string) (*ServerReport, error) {
	var report ServerReport
	dnsResult, err := matrixfederation.LookupServer(serverName)
	if err != nil {
		return nil, err
	}
	report.DNSResult = *dnsResult
	report.ConnectionReports = make(map[string]ConnectionReport)
	report.ConnectionErrors = make(map[string]error)
	now := time.Now()
	for _, addr := range report.DNSResult.Addrs {
		keys, connState, err := matrixfederation.FetchKeysDirect(serverName, addr, sni)
		if err != nil {
			report.ConnectionErrors[addr] = err
			continue
		}
		var connReport ConnectionReport
		for _, cert := range connState.PeerCertificates {
			fingerprint := sha256.Sum256(cert.Raw)
			summary := X509CertSummary{
				cert.Subject.CommonName,
				cert.Issuer.CommonName,
				fingerprint[:],
				cert.DNSNames,
			}
			connReport.Certificates = append(connReport.Certificates, summary)
		}
		connReport.Cipher.Version = enumToString(tlsVersions, connState.Version)
		connReport.Cipher.CipherSuite = enumToString(tlsCipherSuites, connState.CipherSuite)
		connReport.Checks, _, _ = matrixfederation.CheckKeys(serverName, now, *keys, connState)
		raw := json.RawMessage(keys.Raw)
		connReport.Keys = &raw
		report.ConnectionReports[addr] = connReport
	}
	return &report, nil
}

type ReportError struct {
	Message string
}

func (e ReportError) Error() string {
	return e.Message
}

func asReportError(err error) error {
	if err != nil {
		return ReportError{err.Error()}
	} else {
		return nil
	}
}

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

func enumToString(names map[uint16]string, value uint16) string {
	if name, ok := names[value]; ok {
		return name
	} else {
		return fmt.Sprintf("UNKNOWN[0x%x]", value)
	}
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
		// tls.TLS_RSA_WITH_AES_128_GCM_SHA256:         "TLS_RSA_WITH_AES_128_GCM_SHA256",
		// tls.TLS_RSA_WITH_AES_256_GCM_SHA384:         "TLS_RSA_WITH_AES_256_GCM_SHA384",
	}
)
