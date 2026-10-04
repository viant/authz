package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/viant/authz/gating"
)

func TestReadRequirementBindings(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gates.json")
	valid := `[{"resource":{"kind":"window","id":"overview","version":"1","tenant":"owner"},"action":"open","document":{"revision":"v1","requirements":{"schemaVersion":1,"requiredExposures":["feature"]}}}]`
	if err := os.WriteFile(path, []byte(valid), 0600); err != nil {
		t.Fatal(err)
	}
	bindings, err := readRequirementBindings(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(bindings) != 1 || bindings[0].Document.Revision != "v1" {
		t.Fatalf("invalid bindings: %+v", bindings)
	}
	if _, err := gating.NewStaticStore(bindings); err != nil {
		t.Fatal(err)
	}
	for _, malformed := range []string{valid + valid, `[{"unknown":1}]`, `[{"resource":{"kind":"window"}}]`} {
		if err := os.WriteFile(path, []byte(malformed), 0600); err != nil {
			t.Fatal(err)
		}
		bindings, err := readRequirementBindings(path)
		if err == nil {
			_, err = gating.NewStaticStore(bindings)
		}
		if err == nil {
			t.Fatalf("accepted invalid requirement file: %s", malformed)
		}
	}
}

func TestReadAndMatchTrustedGateChoices(t *testing.T) {
	path := filepath.Join(t.TempDir(), "choices.json")
	raw := `[{"resource":{"kind":"window","id":"overview","version":"1","tenant":"owner"},"action":"open","choices":{"roles":[{"id":"reader","label":"Reader"}],"exposures":[{"id":"FEATURE"}]}}]`
	if err := os.WriteFile(path, []byte(raw), 0600); err != nil {
		t.Fatal(err)
	}
	choices, err := readChoiceBindings(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := gating.NewStaticChoices(choices); err != nil {
		t.Fatal(err)
	}
	bindings := []gating.Binding{{Resource: choices[0].Resource, Action: "open", Document: gating.RequirementsDocument{Revision: "r1", Requirements: gating.Requirements{SchemaVersion: 1}}}}
	if err := validateChoiceCoverage(bindings, choices); err != nil {
		t.Fatal(err)
	}
	bindings[0].Action = "edit"
	if err := validateChoiceCoverage(bindings, choices); err == nil {
		t.Fatal("choices for another action accepted")
	}
	if err := os.WriteFile(path, []byte(raw+raw), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readChoiceBindings(path); err == nil {
		t.Fatal("trailing choices accepted")
	}
}
