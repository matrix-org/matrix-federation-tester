package gomatrixserverlib

import (
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
	wellKnown := "https://" + serverName + wellKnownPath

	// Request server's well-known record
	resp, err := http.Get(wellKnown)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = resp.Body.Close()
	}()
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

	if wellKnownResponse.NewAddress == "" {
		return nil, errors.New("No m.server key found in well-known response")
	}

	// Return result
	return wellKnownResponse, nil
}
