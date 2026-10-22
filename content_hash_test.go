package authz

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestContentHashesCanonicalizeEncodingWithoutChangingStructure(t *testing.T) {
	var first, second Document
	for raw, destination := range map[string]*Document{
		`{"resource":{"id":"first","kind":"report","tenant":"one","version":"1"},"revision":7,"policies":{"execute":{"mode":"protected","priority":3,"requiredScopes":["read","run"],"entityType":"account","rule":{"kind":"all","rules":[{"kind":"role","value":"reader"},{"kind":"exposure","value":"REPORTS_UI"}]}},"describe":{"mode":"public"}}}`:     &first,
		`{"policies":{"describe":{"mode":"public"},"execute":{"rule":{"rules":[{"value":"reader","kind":"role"},{"value":"REPORTS_UI","kind":"exposure"}],"kind":"all"},"entityType":"account","requiredScopes":["read","run"],"priority":3,"mode":"protected"}},"revision":99,"resource":{"version":"9","tenant":"other","kind":"window","id":"second"}}`: &second,
	} {
		if err := json.Unmarshal([]byte(raw), destination); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := json.Marshal(first)
	a, err := PoliciesContentHash(first.Policies)
	if err != nil {
		t.Fatal(err)
	}
	b, err := PoliciesContentHash(second.Policies)
	if err != nil {
		t.Fatal(err)
	}
	if a != b || len(a) != 64 {
		t.Fatalf("identical policies with different encoding/resource/revision must share SHA256: %q %q", a, b)
	}
	for n := 0; n < 100; n++ {
		again, err := PoliciesContentHash(first.Policies)
		if err != nil || again != a {
			t.Fatal("unstable map hash", again, err)
		}
	}
	after, _ := json.Marshal(first)
	if string(before) != string(after) {
		t.Fatal("hashing mutated policy document")
	}
	ruleA, err := RuleContentHash(*first.Policies["execute"].Rule)
	if err != nil {
		t.Fatal(err)
	}
	ruleB, err := RuleContentHash(*second.Policies["execute"].Rule)
	if err != nil || ruleA != ruleB {
		t.Fatal("identical rule content differs")
	}
	nilHash, _ := PoliciesContentHash(nil)
	emptyHash, _ := PoliciesContentHash(map[string]Policy{})
	if nilHash != emptyHash {
		t.Fatal("empty deny-all policies must canonicalize")
	}
}

func TestPolicyHashPreservesEveryDecisionAndSelectionField(t *testing.T) {
	base := Policy{Mode: "protected", Priority: 3, RequiredScopes: []string{"read", "run"}, EntityType: "account", Rule: &Rule{Kind: "all", Rules: []Rule{{Kind: "role", Value: "reader"}, {Kind: "entity", Entity: &Entity{Type: "account", ID: "42"}}}}}
	original, _ := json.Marshal(base)
	hash, err := PolicyContentHash("execute", base)
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*Policy){
		"priority":          func(p *Policy) { p.Priority++ },
		"scope value":       func(p *Policy) { p.RequiredScopes[0] = "write" },
		"scope order":       func(p *Policy) { p.RequiredScopes[0], p.RequiredScopes[1] = p.RequiredScopes[1], p.RequiredScopes[0] },
		"entity bound type": func(p *Policy) { p.EntityType = "campaign" },
		"rule operator":     func(p *Policy) { p.Rule.Kind = "any" },
		"rule order":        func(p *Policy) { p.Rule.Rules[0], p.Rule.Rules[1] = p.Rule.Rules[1], p.Rule.Rules[0] },
		"role value":        func(p *Policy) { p.Rule.Rules[0].Value = "editor" },
		"entity value":      func(p *Policy) { p.Rule.Rules[1].Entity.ID = "43" },
		"entity type":       func(p *Policy) { p.Rule.Rules[1].Entity.Type = "campaign" },
		"deny mode":         func(p *Policy) { p.Mode = "deny"; p.Rule = nil; p.EntityType = ""; p.RequiredScopes = nil },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var changed Policy
			if err := json.Unmarshal(original, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(&changed)
			next, err := PolicyContentHash("execute", changed)
			if err != nil {
				t.Fatal(err)
			}
			if next == hash {
				t.Fatal("changed decision content retained same hash")
			}
		})
	}
	otherAction, err := PolicyContentHash("retrieve", base)
	if err != nil || otherAction == hash {
		t.Fatal("action identity omitted")
	}
	after, _ := json.Marshal(base)
	if !reflect.DeepEqual(original, after) {
		t.Fatal("hash mutated input")
	}
}

func TestContentHashRejectsInvalidPolicyOrRule(t *testing.T) {
	for _, rule := range []Rule{{}, {Kind: "all"}, {Kind: "role"}, {Kind: "role", Value: "reader", Rules: []Rule{{Kind: "subject", Value: "a"}}}, {Kind: "entity", Entity: &Entity{ID: "42"}}} {
		hash, err := RuleContentHash(rule)
		if !errors.Is(err, ErrDenied) || hash != "" {
			t.Fatal("invalid rule hashed", hash, err)
		}
	}
	deep := Rule{Kind: "role", Value: "reader"}
	for n := 0; n < 34; n++ {
		deep = Rule{Kind: "all", Rules: []Rule{deep}}
	}
	if hash, err := RuleContentHash(deep); err == nil || hash != "" {
		t.Fatal("deep rule hashed")
	}
	for _, entry := range []struct {
		action string
		policy Policy
	}{
		{"", Policy{Mode: "deny"}}, {"manageAccess", Policy{Mode: "public"}}, {"execute", Policy{Mode: "unknown"}},
		{"execute", Policy{Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}, RequiredScopes: []string{"bad scope"}}},
		{"execute", Policy{Mode: "deny", EntityType: "account"}},
	} {
		hash, err := PolicyContentHash(entry.action, entry.policy)
		if !errors.Is(err, ErrDenied) || hash != "" {
			t.Fatal("invalid policy hashed", hash, err)
		}
		hash, err = PoliciesContentHash(map[string]Policy{entry.action: entry.policy})
		if !errors.Is(err, ErrDenied) || hash != "" {
			t.Fatal("invalid policy map hashed", hash, err)
		}
	}
}

// This benchmark compares standalone content hashing and in-memory evaluation.
// It excludes policy storage, identity issuance, preindexing and request latency.
func BenchmarkPolicyContentHashAndEvaluation(b *testing.B) {
	policy := Policy{Mode: "protected", Priority: 3, RequiredScopes: []string{"report:read"}, Rule: &Rule{Kind: "all", Rules: []Rule{{Kind: "role", Value: "reader"}, {Kind: "exposure", Value: "REPORTS_UI"}}}}
	policies := map[string]Policy{"execute": policy}
	now := time.Date(2026, 10, 22, 8, 0, 0, 0, time.UTC)
	facts := Facts{Subject: "reader", Issuer: "verified", Tenant: "team", Roles: []string{"reader"}, Exposures: []string{"REPORTS_UI"}, GrantedScopes: []string{"report:read"}, ValidUntil: now.Add(time.Hour)}
	request := Request{Resource: Resource{Kind: "report", ID: "report://team/summary", Tenant: "team", Version: "1"}, Action: "execute"}
	b.Run("rule-hash", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			if _, err := RuleContentHash(*policy.Rule); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("policy-hash", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			if _, err := PolicyContentHash("execute", policy); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("action-map-hash", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			if _, err := PoliciesContentHash(policies); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("evaluate", func(b *testing.B) {
		b.ReportAllocs()
		for n := 0; n < b.N; n++ {
			if _, err := Evaluate(request, policies, facts, now); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func TestContentHashV1EncodingContract(t *testing.T) {
	rule := Rule{Kind: "role", Value: "reader"}
	hash, err := RuleContentHash(rule)
	if err != nil {
		t.Fatal(err)
	}
	if hash != "463632ee5b29b57e810072c397ad7f9bf279ffe26998c197635041820d955cc3" {
		t.Fatal("v1 rule encoding changed", hash)
	}
	policy := Policy{Mode: "protected", Rule: &rule}
	hash, err = PolicyContentHash("execute", policy)
	if err != nil {
		t.Fatal(err)
	}
	if hash != "8a16a510e066138040abcb16015637bd68a53e71203e4d97a449e106dfbccd89" {
		t.Fatal("v1 policy encoding changed", hash)
	}
	policy.RequiredScopes = []string{}
	empty, err := PolicyContentHash("execute", policy)
	if err != nil || empty != hash {
		t.Fatal("nil/empty optional scopes changed content identity", empty, err)
	}
}
