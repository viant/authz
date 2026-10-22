package authz

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// RuleContentHash identifies one validated, ordered rule tree. It contains no
// resource, policy revision or principal facts and grants no authority. The
// authored all/any order is retained; this is not logical-equivalence reduction.
func RuleContentHash(rule Rule) (string, error) {
	if !valid(rule, 0) {
		return "", ErrDenied
	}
	return contentHash(struct {
		Format string `json:"format"`
		Rule   Rule   `json:"rule"`
	}{"authz.rule.v1", rule})
}

// PolicyContentHash identifies validated policy content for an action. Action
// identity, priority, scopes, entity type and the complete ordered rule tree are
// included. Resource identity and revision must remain separate cache fences.
func PolicyContentHash(action string, policy Policy) (string, error) {
	if err := ValidatePolicy(action, policy); err != nil {
		return "", err
	}
	return contentHash(struct {
		Format string `json:"format"`
		Action string `json:"action"`
		Policy Policy `json:"policy"`
	}{"authz.policy.v1", action, policy})
}

// PoliciesContentHash identifies an action-policy map independently of resource
// identity and revision. JSON map keys are sorted; rule/scope slice order is
// preserved. Nil and empty maps both represent the same deny-all policy content.
// Callers must not mutate the input concurrently, as with policy evaluation.
func PoliciesContentHash(policies map[string]Policy) (string, error) {
	for action, policy := range policies {
		if err := ValidatePolicy(action, policy); err != nil {
			return "", err
		}
	}
	if len(policies) == 0 {
		policies = map[string]Policy{}
	}
	return contentHash(struct {
		Format   string            `json:"format"`
		Policies map[string]Policy `json:"policies"`
	}{"authz.policies.v1", policies})
}

func contentHash(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
