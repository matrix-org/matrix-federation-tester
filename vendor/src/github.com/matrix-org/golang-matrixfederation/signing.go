package matrixfederation

import (
	"encoding/json"
	"fmt"
	"golang.org/x/crypto/ed25519"
)

// SignJSON signs a JSON object returning a copy signed with the given key.
// https://matrix.org/docs/spec/server_server/unstable.html#signing-json
func SignJSON(signingName, keyID string, privateKey ed25519.PrivateKey, message []byte) ([]byte, error) {
	var object map[string]*json.RawMessage
	var signatures map[string]map[string]Base64String
	if err := json.Unmarshal(message, &object); err != nil {
		return nil, err
	}

	rawUnsigned, hasUnsigned := object["unsigned"]
	delete(object, "unsigned")

	if rawSignatures := object["signatures"]; rawSignatures != nil {
		if err := json.Unmarshal(*rawSignatures, &signatures); err != nil {
			return nil, err
		}
		delete(object, "signatures")
	} else {
		signatures = map[string]map[string]Base64String{}
	}

	unsorted, err := json.Marshal(object)
	if err != nil {
		return nil, err
	}

	canonical, err := CanonicalJSON(unsorted)
	if err != nil {
		return nil, err
	}

	signature := Base64String(ed25519.Sign(privateKey, canonical))

	signaturesForEntity := signatures[signingName]
	if signaturesForEntity != nil {
		signaturesForEntity[keyID] = signature
	} else {
		signatures[signingName] = map[string]Base64String{keyID: signature}
	}

	var rawSignatures json.RawMessage
	rawSignatures, err = json.Marshal(signatures)
	if err != nil {
		return nil, err
	}

	object["signatures"] = &rawSignatures
	if hasUnsigned {
		object["unsigned"] = rawUnsigned
	}

	return json.Marshal(object)
}

// VerifyJSON checks that the entity has signed the message using a particular key.
func VerifyJSON(signingName, keyID string, publicKey ed25519.PublicKey, message []byte) error {
	var object map[string]*json.RawMessage
	var signatures map[string]map[string]Base64String
	if err := json.Unmarshal(message, &object); err != nil {
		return err
	}
	delete(object, "unsigned")

	if object["signatures"] == nil {
		return fmt.Errorf("No signatures")
	}

	if err := json.Unmarshal(*object["signatures"], &signatures); err != nil {
		return err
	}
	delete(object, "signatures")

	signature, ok := signatures[signingName][keyID]
	if !ok {
		return fmt.Errorf("No signature from %q with ID %q", signingName, keyID)
	}

	if len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("Bad signature length from %q with ID %q", signingName, keyID)
	}

	unsorted, err := json.Marshal(object)
	if err != nil {
		return err
	}

	canonical, err := CanonicalJSON(unsorted)
	if err != nil {
		return err
	}

	if !ed25519.Verify(publicKey, canonical, signature) {
		return fmt.Errorf("Bad signature from %q with ID %q", signingName, keyID)
	}

	return nil
}
