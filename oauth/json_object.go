package oauth

import (
	"bytes"
	"encoding/json"
	access "github.com/viant/authz"
	"io"
	"strings"
)

func uniqueObject(raw []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return nil, access.ErrDenied
	}
	result := map[string]json.RawMessage{}
	seen := map[string]bool{}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[strings.ToLower(name)] {
			return nil, access.ErrDenied
		}
		seen[strings.ToLower(name)] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return nil, access.ErrDenied
		}
		result[name] = value
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, access.ErrDenied
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, access.ErrDenied
	}
	return result, nil
}
