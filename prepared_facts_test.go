package authz

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

func linearPreparedRuleOracle(rule Rule, facts Facts) bool {
	contains := func(values []string, wildcard bool) bool {
		for _, value := range values {
			if value != "" && (value == rule.Value || wildcard && rule.Value == "*") {
				return true
			}
		}
		return false
	}
	switch rule.Kind {
	case "role":
		return contains(facts.Roles, true)
	case "exposure":
		return contains(facts.Exposures, true)
	case "group":
		return contains(facts.MembershipGroups, false)
	case "subject":
		return facts.Subject != "" && (facts.Subject == rule.Value || rule.Value == "*")
	case "all":
		for _, child := range rule.Rules {
			if !linearPreparedRuleOracle(child, facts) {
				return false
			}
		}
		return true
	case "any":
		for _, child := range rule.Rules {
			if linearPreparedRuleOracle(child, facts) {
				return true
			}
		}
		return false
	}
	return false
}
func TestPreparedFactsMatchesLinearMembershipSemantics(t *testing.T) {
	now := time.Now()
	resource := Resource{Kind: "window", ID: "one", Version: "1", Tenant: "tenant"}
	values := [][]string{nil, {}, {""}, {"reader"}, {"*"}, {"other", "reader", "reader", ""}}
	for _, roles := range values {
		for _, exposures := range values {
			for _, groups := range values {
				facts := Facts{Subject: "alice", Issuer: "verified", Tenant: "tenant", Roles: roles, Exposures: exposures, MembershipGroups: groups, ValidUntil: now.Add(time.Minute)}
				prepared := PrepareFacts(facts)
				for _, kind := range []string{"role", "exposure", "group"} {
					for _, value := range []string{"reader", "*", "missing"} {
						leaf := Rule{Kind: kind, Value: value}
						rules := []Rule{leaf, {Kind: "any", Rules: []Rule{leaf, {Kind: "subject", Value: "other"}}}, {Kind: "all", Rules: []Rule{leaf, {Kind: "subject", Value: "alice"}}}}
						for _, rule := range rules {
							policy := map[string]Policy{"open": {Mode: "protected", Rule: &rule}}
							_, err := EvaluatePrepared(Request{Resource: resource, Action: "open"}, policy, prepared, now)
							if (err == nil) != linearPreparedRuleOracle(rule, facts) {
								t.Fatalf("kind=%s value=%s roles=%v exposures=%v groups=%v err=%v", kind, value, roles, exposures, groups, err)
							}
						}
					}
				}
				if prepared.HasRoleLiteral("*") != literalStringOracle(roles, "*") || prepared.HasExposureLiteral("*") != literalStringOracle(exposures, "*") || prepared.HasGroup("*") != literalStringOracle(groups, "*") {
					t.Fatal("literal membership became wildcard")
				}
			}
		}
	}
}
func literalStringOracle(values []string, want string) bool {
	for _, value := range values {
		if value != "" && value == want {
			return true
		}
	}
	return false
}
func TestPreparedFactsOwnsAllMutableInputAndOutput(t *testing.T) {
	now := time.Now()
	facts := Facts{Subject: "alice", Issuer: "verified", Tenant: "tenant", Roles: []string{"reader"}, Exposures: []string{"feature"}, MembershipGroups: []string{"internal"}, GrantedScopes: []string{"read"}, EntityGroups: EntityGroups{"account": []EntityID{"7"}}, EntityPermissions: []EntityPermission{{Type: "account", ID: "7", Permissions: []string{"read"}}}, ValidUntil: now.Add(time.Minute)}
	prepared := PrepareFacts(facts)
	expected := prepared.Facts()
	facts.Roles[0] = "changed"
	facts.Exposures[0] = "changed"
	facts.MembershipGroups[0] = "changed"
	facts.GrantedScopes[0] = "changed"
	facts.EntityGroups["account"][0] = "8"
	facts.EntityGroups["extra"] = []EntityID{"9"}
	facts.EntityPermissions[0].Permissions[0] = "changed"
	exported := prepared.Facts()
	exported.Roles[0] = "changed again"
	exported.Exposures[0] = "changed again"
	exported.MembershipGroups[0] = "changed again"
	exported.EntityGroups["account"][0] = "9"
	exported.EntityPermissions[0].Permissions[0] = "changed again"
	exported.GrantedScopes[0] = "changed again"
	if !reflect.DeepEqual(prepared.Facts(), expected) {
		t.Fatal("prepared snapshot shares mutable facts")
	}
	rule := Rule{Kind: "all", Rules: []Rule{{Kind: "role", Value: "reader"}, {Kind: "exposure", Value: "feature"}, {Kind: "group", Value: "internal"}, {Kind: "entity", Entity: &Entity{Type: "account", ID: "7"}}}}
	resource := Resource{Kind: "window", ID: "one", Tenant: "tenant"}
	selection := []Entity{{Type: "account", ID: "7"}}
	decision, err := EvaluatePrepared(Request{Resource: resource, Action: "open", Selection: &selection}, map[string]Policy{"open": {Mode: "protected", Rule: &rule, RequiredScopes: []string{"read"}, EntityType: "account"}}, prepared, now)
	if err != nil || !decision.Bounded || !reflect.DeepEqual(decision.Entities, selection) {
		t.Fatalf("snapshot changed evaluation: %+v %v", decision, err)
	}
	decision.Entities[0].ID = "mutated-result"
	again, err := EvaluatePrepared(Request{Resource: resource, Action: "open", Selection: &selection}, map[string]Policy{"open": {Mode: "protected", Rule: &rule, RequiredScopes: []string{"read"}, EntityType: "account"}}, prepared, now)
	if err != nil || again.Entities[0].ID != "7" {
		t.Fatal("decision escaped mutable snapshot")
	}
	second := PrepareFacts(facts)
	if second.HasRoleLiteral("reader") || second.HasExposureLiteral("feature") || second.HasGroup("internal") {
		t.Fatal("snapshots shared principal membership")
	}
}
func TestPreparedFactsPreservesPublicInvalidFactsAndProtectedBoundaries(t *testing.T) {
	now := time.Now()
	r := Resource{Kind: "window", ID: "one", Tenant: "tenant"}
	base := Facts{Subject: "alice", Issuer: "verified", Tenant: "tenant", Roles: []string{"reader"}, GrantedScopes: []string{"read"}, Entities: []Entity{{Type: "account", ID: "7"}}, ValidUntil: now.Add(time.Minute)}
	cases := []struct {
		name    string
		change  func(*Facts)
		policy  Policy
		action  string
		allowed bool
	}{
		{"protected", func(*Facts) {}, Policy{Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}, RequiredScopes: []string{"read"}}, "open", true},
		{"expired", func(f *Facts) { f.ValidUntil = now }, Policy{Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}}, "open", false},
		{"tenant", func(f *Facts) { f.Tenant = "other" }, Policy{Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}}, "open", false},
		{"invalid scopes", func(f *Facts) { f.GrantedScopes = []string{"read", "read"} }, Policy{Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}}, "open", false},
		{"invalid entities", func(f *Facts) { f.Entities = []Entity{{Type: "account", ID: ""}} }, Policy{Mode: "protected", Rule: &Rule{Kind: "role", Value: "reader"}}, "open", false},
		{"public ignores unused invalid facts", func(f *Facts) {
			f.Entities = []Entity{{Type: "account", ID: ""}}
			f.GrantedScopes = []string{"read", "read"}
		}, Policy{Mode: "public"}, "describe", true},
		{"public management forbidden", func(*Facts) {}, Policy{Mode: "public"}, "manageAccess", false},
		{"unresolved named denied", func(*Facts) {}, Policy{Mode: "named", Rule: &Rule{Kind: "role", Value: "reader"}}, "open", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			facts := clonePreparedFacts(base)
			tc.change(&facts)
			policies := map[string]Policy{tc.action: tc.policy}
			decision, err := EvaluatePrepared(Request{Resource: r, Action: tc.action}, policies, PrepareFacts(facts), now)
			if (err == nil) != tc.allowed {
				t.Fatalf("decision=%v err=%v", decision, err)
			}
			if err != nil && !errors.Is(err, ErrDenied) {
				t.Fatal(err)
			}
		})
	}
}

func BenchmarkEvaluatePreparedLargeFacts(b *testing.B) {
	for _, size := range []int{1, 1000, 100000} {
		b.Run(fmt.Sprintf("memberships_%d", size), func(b *testing.B) {
			now := time.Now()
			facts := Facts{Subject: "alice", Issuer: "verified", Tenant: "tenant", ValidUntil: now.Add(time.Hour)}
			for i := 0; i < size; i++ {
				value := fmt.Sprintf("member-%d", i)
				facts.Roles = append(facts.Roles, value)
				facts.Exposures = append(facts.Exposures, value)
				facts.MembershipGroups = append(facts.MembershipGroups, value)
			}
			last := facts.Roles[size-1]
			rule := Rule{Kind: "all", Rules: []Rule{{Kind: "role", Value: last}, {Kind: "exposure", Value: last}, {Kind: "group", Value: last}}}
			policies := map[string]Policy{"open": {Mode: "protected", Rule: &rule}}
			request := Request{Resource: Resource{Kind: "window", ID: "one", Tenant: "tenant"}, Action: "open"}
			prepared := PrepareFacts(facts)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if _, err := EvaluatePrepared(request, policies, prepared, now); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// Preparation is timed separately so request-side cloning/set construction
// costs are visible alongside the zero-allocation repeated membership checks.
func BenchmarkPrepareFactsLargeMemberships(b *testing.B) {
	for _, size := range []int{1000, 100000} {
		b.Run(fmt.Sprintf("memberships_%d", size), func(b *testing.B) {
			facts := Facts{Subject: "alice", Issuer: "verified", Tenant: "tenant", ValidUntil: time.Now().Add(time.Hour)}
			for i := 0; i < size; i++ {
				value := fmt.Sprintf("member-%d", i)
				facts.Roles = append(facts.Roles, value)
				facts.Exposures = append(facts.Exposures, value)
				facts.MembershipGroups = append(facts.MembershipGroups, value)
			}
			// Include nested entity facts in the snapshot cost without generating a
			// synthetic provider decision or changing their authorization semantics.
			facts.EntityGroups = EntityGroups{"account": []EntityID{"7"}}
			facts.EntityPermissions = []EntityPermission{{Type: "account", ID: "7", Permissions: []string{"read"}}}
			last := facts.Roles[size-1]
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				prepared := PrepareFacts(facts)
				if !prepared.HasRoleLiteral(last) || !prepared.HasExposureLiteral(last) || !prepared.HasGroup(last) {
					b.Fatal("membership lost")
				}
			}
		})
	}
}
