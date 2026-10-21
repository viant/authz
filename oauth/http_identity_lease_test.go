package oauth

import (
	"encoding/json"
	"testing"
	"time"
)

func TestIdentityDefaultHourLeaseRemainsBoundedByTokenExpiry(t *testing.T) {
	_, _, base := cacheFixture(t)
	for _, lease := range []string{"", "1h"} {
		c := base
		c.FactLease = lease
		p, err := newHTTPIdentity(c)
		if err != nil || p.lease != time.Hour {
			t.Fatalf("default/hour lease: %v %v", p, err)
		}
	}
	now := time.Now()
	expiry := now.Add(20 * time.Minute)
	until, err := deadlineHTTPWithLimit(now, now, expiry, time.Hour, 0, json.RawMessage(`{}`), "evaluatedAt", "validUntil", false, time.Hour)
	if err != nil || !until.Equal(expiry) {
		t.Fatalf("lease exceeded JWT expiry: %v %v", until, err)
	}
	until, err = deadlineHTTPWithLimit(now, now, now.Add(2*time.Hour), time.Hour, 0, json.RawMessage(`{}`), "evaluatedAt", "validUntil", false, time.Hour)
	if err != nil || !until.Equal(now.Add(time.Hour)) {
		t.Fatalf("default hour not enforced: %v %v", until, err)
	}
	if _, err = deadlineHTTPWithLimit(now, now, expiry, time.Hour, 0, json.RawMessage(`{}`), "evaluatedAt", "validUntil", true, time.Hour); err == nil {
		t.Fatal("required authority lease bypassed")
	}
}
