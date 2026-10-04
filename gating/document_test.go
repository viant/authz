package gating

import (
	"errors"
	"testing"
)

func TestDecodeActionRequirementsRejectsAmbiguousOrInvalidDocuments(t *testing.T) {
	valid, err := DecodeActionRequirements([]byte(`{"discover":{"schemaVersion":1},"execute":{"schemaVersion":1,"requiredExposures":["FEATURE_X"]}}`))
	if err != nil || len(valid) != 2 || valid["execute"].RequiredExposures[0] != "FEATURE_X" {
		t.Fatalf("valid document=%+v err=%v", valid, err)
	}
	for _, raw := range []string{
		`{}`,
		`{"execute":{"schemaVersion":1},"execute":{"schemaVersion":1}}`,
		`{"execute":{"schemaVersion":2}}`,
		`{"execute":{"schemaVersion":1,"unknown":true}}`,
		`{"execute":{"schemaVersion":1,"entitlement":{"providerRef":"p","key":"k","scope":"entity"}}}`,
	} {
		if _, err := DecodeActionRequirements([]byte(raw)); !errors.Is(err, ErrInvalidRequirements) {
			t.Fatalf("invalid document %q accepted: %v", raw, err)
		}
	}
}
