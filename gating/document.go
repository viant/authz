package gating

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

var ErrInvalidRequirements = errors.New("invalid gate requirements document")

// DecodeActionRequirements validates a versioned requirements document keyed
// by canonical action. It rejects duplicate keys and unknown nested fields so
// readers and writers cannot interpret the same stored bytes differently.
func DecodeActionRequirements(payload []byte) (map[string]Requirements, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, ErrInvalidRequirements
	}
	result := map[string]Requirements{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, ErrInvalidRequirements
		}
		action, ok := token.(string)
		if !ok || action == "" || strings.TrimSpace(action) != action {
			return nil, ErrInvalidRequirements
		}
		if _, exists := result[action]; exists {
			return nil, ErrInvalidRequirements
		}
		var raw json.RawMessage
		if err := decoder.Decode(&raw); err != nil {
			return nil, ErrInvalidRequirements
		}
		entry := json.NewDecoder(bytes.NewReader(raw))
		entry.DisallowUnknownFields()
		var requirements Requirements
		if err := entry.Decode(&requirements); err != nil || !validRequirements(requirements) {
			return nil, ErrInvalidRequirements
		}
		result[action] = requirements
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') || len(result) == 0 {
		return nil, ErrInvalidRequirements
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, ErrInvalidRequirements
	}
	return result, nil
}
