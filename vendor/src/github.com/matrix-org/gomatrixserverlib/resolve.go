/* Copyright 2016-2017 Vector Creations Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package gomatrixserverlib

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// ResolutionResult is a result of looking up a Matrix homeserver according to
// the federation specification.
type ResolutionResult struct {
	Destination   string     // The hostname and port to send federation requests to.
	Host          ServerName // The value of the Host headers.
	TLSServerName string     // The TLS server name to request a certificate for.
}

// A HostResult is the result of looking up the IP addresses for a host.
type HostResult struct {
	CName string   // The canonical name for the host.
	Addrs []string // The IP addresses for the host.
	Error error    // If there was an error getting the IP addresses.
}

// A DNSResult is the result of looking up a matrix server in DNS.
type DNSResult struct {
	SRVCName   string                // The canonical name for the SRV record in DNS
	SRVRecords []*net.SRV            // List of SRV record for the matrix server.
	SRVError   error                 // If there was an error getting the SRV records.
	Hosts      map[string]HostResult // The results of looking up the SRV record targets.
	Addrs      []string              // List of "<ip>:<port>" strings that the server is listening on. These strings can be passed to `net.Dial()`.
}

// LookupServer looks up a matrix server in DNS.
// This function is rendered obsolete by ResolveServer, and will be removed in
// the future.
func LookupServer(serverName ServerName) (*DNSResult, error) { // nolint: gocyclo
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
				// If there isn't a SRV record in DNS then fallback to "serverName:8448".
				hosts[string(serverName)] = []net.SRV{{
					Target: string(serverName),
					Port:   8448,
				}}
			}
		} else {
			// Group the SRV records by target host.
			for _, record := range result.SRVRecords {
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
		cname, _ := net.LookupCNAME(host)
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

// ResolveServer implements the server name resolution algorithm described at
// https://matrix.org/docs/spec/server_server/r0.1.1.html#resolving-server-names
// Returns a slice of ResolutionResult that can be used to send a federation
// request to the server using a given server name.
// Returns an error if the server name isn't valid.
func ResolveServer(serverName ServerName) (results []ResolutionResult, err error) {
	return resolveServer(serverName, true)
}

// resolveServer does the same thing as ResolveServer, except it also requires
// the checkWellKnown parameter, which indicates whether a .well-known file
// should be looked up.
func resolveServer(serverName ServerName, checkWellKnown bool) (results []ResolutionResult, err error) {
	host, port, valid := ParseAndValidateServerName(serverName)
	if !valid {
		err = fmt.Errorf("Invalid server name")
		return
	}

	// 1. If the hostname is an IP literal
	// Check if we're dealing with an IPv6 literal with square brackets. If so,
	// remove the brackets.
	if host[0] == '[' && host[len(host)-1] == ']' {
		host = host[1 : len(host)-1]
	}
	if net.ParseIP(host) != nil {
		var destination string

		if port == -1 {
			destination = net.JoinHostPort(host, strconv.Itoa(8448))
		} else {
			destination = string(serverName)
		}

		results = []ResolutionResult{
			ResolutionResult{
				Destination:   destination,
				Host:          serverName,
				TLSServerName: host,
			},
		}

		return
	}

	// 2. If the hostname is not an IP literal, and the server name includes an
	// explicit port
	if port != -1 {
		results = []ResolutionResult{
			ResolutionResult{
				Destination:   string(serverName),
				Host:          serverName,
				TLSServerName: host,
			},
		}

		return
	}

	if checkWellKnown {
		// 3. If the hostname is not an IP literal
		var result *WellKnownResult
		result, err = LookupWellKnown(serverName)
		if err == nil {
			// We don't want to check .well-known on the result
			return resolveServer(result.NewAddress, false)
		}
	}

	return handleNoWellKnown(serverName), nil
}

// handleNoWellKnown implements steps 4 and 5 of the resolution algorithm (as
// well as 3.3 and 3.4)
func handleNoWellKnown(serverName ServerName) (results []ResolutionResult) {
	// 4. If the /.well-known request resulted in an error response
	_, records, err := net.LookupSRV("matrix", "tcp", string(serverName))
	if err == nil && len(records) > 0 {
		for _, rec := range records {
			// If the domain is a FQDN, remove the trailing dot at the end. This
			// isn't critical to send the request, as Go's HTTP client and most
			// servers understand FQDNs quite well, but it makes automated
			// testing easier.
			target := rec.Target
			if target[len(target)-1] == '.' {
				target = target[:len(target)-1]
			}

			results = append(results, ResolutionResult{
				Destination:   fmt.Sprintf("%s:%d", target, rec.Port),
				Host:          serverName,
				TLSServerName: string(serverName),
			})
		}

		return
	}

	// 5. If the /.well-known request returned an error response, and the SRV
	// record was not found
	results = []ResolutionResult{
		ResolutionResult{
			Destination:   fmt.Sprintf("%s:%d", serverName, 8448),
			Host:          serverName,
			TLSServerName: string(serverName),
		},
	}

	return
}
