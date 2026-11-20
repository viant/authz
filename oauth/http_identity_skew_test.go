package oauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/viant/authz"
)

func TestHTTPIdentityConfigurableSourceClockSkew(t *testing.T) {
	for _, tt := range []struct {
		name, skew string
		offset     time.Duration
		allowed    bool
	}{
		{"strict default", "", 45 * time.Second, false},
		{"sixty seconds", "60s", 45 * time.Second, true},
		{"beyond sixty seconds", "60s", 65 * time.Second, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			f := newAuthorityHTTPFixture(t)
			evaluated := time.Now().Add(tt.offset)
			f.info["evaluatedAt"] = evaluated.UTC().Format(time.RFC3339Nano)
			f.info["validUntil"] = evaluated.Add(5 * time.Minute).UTC().Format(time.RFC3339Nano)
			c := f.config()
			c.SourceClockSkew = tt.skew
			c.FactLease = "2m"
			p, err := NewHTTPProviders(context.Background(), c, nil)
			if err != nil {
				t.Fatal(err)
			}
			ctx := WithBearer(context.Background(), f.token(t, 21, f.server.URL, "configured-client"))
			facts, err := p.Identity.Resolve(ctx)
			if tt.allowed {
				if err != nil || !facts.ValidUntil.After(time.Now()) {
					t.Fatalf("expected usable facts: %v", err)
				}
			} else if !errors.Is(err, authz.ErrDenied) {
				t.Fatalf("expected denial: %v", err)
			}
		})
	}
}

func TestHTTPIdentityRejectsInvalidSourceClockSkew(t *testing.T) {
	f := newAuthorityHTTPFixture(t)
	for _, skew := range []string{"-1s", "60001ms", "invalid"} {
		c := f.config()
		c.SourceClockSkew = skew
		if _, err := NewHTTPProviders(context.Background(), c, nil); err == nil {
			t.Fatalf("accepted %q", skew)
		}
	}
}

func TestSourceClockSkewDeadlineAndSafeDiagnostics(t *testing.T) {
	var output bytes.Buffer
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewJSONHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))
	t.Cleanup(func() { slog.SetDefault(previous) })
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		name                    string
		evaluated, until, token time.Time
		allowed                 bool
		reason                  string
	}{
		{"bounded", now.Add(45 * time.Second), now.Add(5 * time.Minute), now.Add(10 * time.Minute), true, ""},
		{"future", now.Add(61 * time.Second), now.Add(5 * time.Minute), now.Add(10 * time.Minute), false, "source_clock_ahead"},
		{"source expired", now.Add(-2 * time.Minute), now.Add(-time.Second), now.Add(10 * time.Minute), false, "effective_lease_expired"},
		{"token expired", now, now.Add(5 * time.Minute), now.Add(-time.Second), false, "effective_lease_expired"},
		{"short source lease", now, now.Add(30 * time.Second), now.Add(10 * time.Minute), false, "effective_lease_expired"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			output.Reset()
			raw, _ := json.Marshal(map[string]any{"evaluatedAt": tt.evaluated, "validUntil": tt.until, "token": "TOKEN_CANARY", "customerRecord": "PAYLOAD_CANARY"})
			deadline, err := deadlineHTTPWithLimit(context.Background(), now, now, tt.token, 2*time.Minute, time.Minute, raw, "evaluatedAt", "validUntil", true, time.Hour)
			if tt.allowed {
				want := tt.evaluated.Add(time.Minute)
				if err != nil || !deadline.Equal(want) || deadline.After(tt.token) || deadline.After(tt.until.Add(-time.Minute)) {
					t.Fatalf("deadline %v want %v, error %v", deadline, want, err)
				}
				if output.Len() != 0 {
					t.Fatal("success should not emit rejection log")
				}
			} else {
				if !errors.Is(err, authz.ErrDenied) {
					t.Fatalf("denial identity lost: %v", err)
				}
				var event map[string]any
				if err = json.Unmarshal(output.Bytes(), &event); err != nil {
					t.Fatal(err)
				}
				if event["reason"] != tt.reason || event["configuredSkewMs"] != float64(60000) {
					t.Fatal(event)
				}
				if strings.Contains(output.String(), "CANARY") {
					t.Fatal("sensitive source content logged")
				}
			}
		})
	}
}
