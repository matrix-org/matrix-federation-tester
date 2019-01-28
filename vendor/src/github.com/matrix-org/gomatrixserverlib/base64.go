package matrixfederation

import (
	"encoding/base64"
	"encoding/json"
)

// A Base64String is a string of bytes that are base64 encoded when used in JSON.
// The bytes encoded using base64 when marshalled as JSON.
// When the bytes are unmarshalled from JSON they are decoded from base64.
type Base64String []byte

// MarshalJSON encodes the bytes as base64 and then encodes the base64 as a JSON string.
// This takes a value receiver so that maps and slices of Base64String encode correctly.
func (b64 Base64String) MarshalJSON() ([]byte, error) {
	// This could be made more efficient by using base64.RawStdEncoding.Encode
	// to write the base64 directly to the JSON. We don't need to JSON escape
	// any of the characters used in base64.
	return json.Marshal(base64.RawStdEncoding.EncodeToString(b64))
}

// UnmarshalJSON decodes a JSON string and then decodes the resulting base64.
// This takes a pointer receiver because it needs to write the result of decoding.
func (b64 *Base64String) UnmarshalJSON(raw []byte) (err error) {
	// We could add a fast path that used base64.RawStdEncoding.Decode
	// directly on the raw JSON if the JSON didn't contain any escapes.
	var str string
	if err = json.Unmarshal(raw, &str); err != nil {
		return
	}
	*b64, err = base64.RawStdEncoding.DecodeString(str)
	return
}
