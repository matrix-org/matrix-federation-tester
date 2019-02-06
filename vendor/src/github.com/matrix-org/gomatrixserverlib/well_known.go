package gomatrixserverlib

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
)

// WellKnownResult is the result of looking up a matrix server's well-known file.
// Located at https://<server_name>/.well-known/matrix/server
type WellKnownResult struct {
	NewAddress ServerName `json:"m.server"`
}

// LookupWellKnown looks up a well-known record for a matrix server. If one if
// found, it returns the server to redirect to.
func LookupWellKnown(serverNameType ServerName) (*WellKnownResult, error) {
	serverName := string(serverNameType)

	// Handle ending "/"
	strings.Trim(serverName, "/")

	wellKnownPath := "/.well-known/matrix/server"
	wellKnown := "http://" + serverName + wellKnownPath

	// The http lib seems to choke on Let's Encrypt here
	// We don't require HTTPS for this endpoint anyways, so disable certificate verification
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr}

	// Request server's well-known record
	resp, err := client.Get(wellKnown)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != 200 {
		return nil, errors.New("No .well-known found")
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	// Convert result to JSON
	wellKnownResponse := &WellKnownResult{}
	err = json.Unmarshal(body, wellKnownResponse)
	if err != nil {
		return nil, err
	}

	// Return result
	return wellKnownResponse, nil
}
