package oauth

import (
	"context"
	"encoding/json"
	"github.com/viant/authz"
	"testing"
	"time"
)

func TestHTTPEvaluationSourceClockSkew(t *testing.T) {
	for _, test := range []struct {
		name, skew string
		offset     time.Duration
		allow      bool
	}{
		{"strict default", "", 3 * time.Second, false},
		{"explicit bounded skew", "5s", 3 * time.Second, true},
		{"beyond configured bound", "5s", 6 * time.Second, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			f := newAuthorityHTTPFixture(t)
			f.overrideEvaluation = func(info map[string]any) {
				evaluated := time.Now().Add(test.offset)
				info["evaluatedAt"] = evaluated.UTC().Format(time.RFC3339Nano)
				info["validUntil"] = evaluated.Add(time.Minute).UTC().Format(time.RFC3339Nano)
			}
			config := f.evaluation()
			raw, _ := json.Marshal(config)
			var encoded map[string]any
			_ = json.Unmarshal(raw, &encoded)
			encoded["sourceClockSkew"] = test.skew
			raw, _ = json.Marshal(encoded)
			_ = json.Unmarshal(raw, &config)
			providers, err := NewHTTPProviders(context.Background(), f.config(), &config)
			if err != nil {
				t.Fatal(err)
			}
			ctx := WithBearer(context.Background(), f.token(t, 21, f.server.URL, "configured-client"))
			facts, err := providers.Identity.Resolve(ctx)
			if err != nil {
				t.Fatal(err)
			}
			allowed, until, err := providers.PermissionWithLease(ctx, facts, authz.Entity{Type: "document", ID: "101"}, "read")
			if test.allow {
				if err != nil || !allowed {
					t.Fatalf("configured in-bound source clock was rejected: %v", err)
				}
				if !until.After(time.Now()) || until.After(facts.ValidUntil) {
					t.Fatal("source tolerance must not extend verified fact deadline")
				}
			} else if err == nil {
				t.Fatal("unconfigured or out-of-bound future source must be rejected")
			}
		})
	}
}

func TestHTTPEvaluationRejectsInvalidClockSkew(t *testing.T) {
	f := newAuthorityHTTPFixture(t)
	for _, value := range []string{"-1s", "5001ms", "invalid"} {
		t.Run(value, func(t *testing.T) {
			config := f.evaluation()
			config.SourceClockSkew = value
			if _, err := NewHTTPProviders(context.Background(), f.config(), &config); err == nil {
				t.Fatal("invalid evaluation clock tolerance accepted")
			}
		})
	}
}
func TestHTTPEvaluationClockSkewCannotReviveExpiredLease(t *testing.T) {
	f := newAuthorityHTTPFixture(t)
	f.overrideEvaluation = func(info map[string]any) {
		info["evaluatedAt"] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339Nano)
		info["validUntil"] = time.Now().Add(-time.Millisecond).UTC().Format(time.RFC3339Nano)
	}
	config := f.evaluation()
	config.SourceClockSkew = "5s"
	providers, err := NewHTTPProviders(context.Background(), f.config(), &config)
	if err != nil {
		t.Fatal(err)
	}
	ctx := WithBearer(context.Background(), f.token(t, 21, f.server.URL, "configured-client"))
	facts, err := providers.Identity.Resolve(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = providers.PermissionWithLease(ctx, facts, authz.Entity{Type: "document", ID: "101"}, "read"); err == nil {
		t.Fatal("clock skew revived expired evaluation")
	}
}
