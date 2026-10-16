package oauth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/viant/authz"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

func httpEndpoint(raw string) (*url.URL, error) {
	u, e := url.Parse(raw)
	if e != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && loopbackHost(u.Hostname()))) {
		return nil, fmt.Errorf("authority endpoint requires HTTPS or loopback HTTP without credentials/query")
	}
	return u, nil
}
func authorityClient(c *http.Client) *http.Client {
	out := http.Client{Timeout: 5 * time.Second}
	if c != nil {
		out = *c
		if out.Timeout <= 0 {
			out.Timeout = 5 * time.Second
		}
	}
	out.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &out
}
func validHTTPPath(path string) bool {
	if path == "" || len(path) > 256 {
		return false
	}
	for _, part := range strings.Split(path, ".") {
		if part == "" || strings.TrimSpace(part) != part || strings.ContainsAny(part, "[]/\\") {
			return false
		}
		switch part {
		case "__proto__", "constructor", "prototype":
			return false
		}
	}
	return true
}
func rawHTTPPath(raw json.RawMessage, path string) (json.RawMessage, bool, error) {
	if !validHTTPPath(path) {
		return nil, false, authz.ErrDenied
	}
	for _, part := range strings.Split(path, ".") {
		object, e := uniqueObject(raw)
		if e != nil {
			return nil, false, authz.ErrDenied
		}
		count := 0
		for key := range object {
			if strings.EqualFold(key, part) {
				count++
			}
		}
		if count > 1 {
			return nil, false, authz.ErrDenied
		}
		value, found := object[part]
		if !found {
			return nil, false, nil
		}
		raw = value
	}
	return raw, true, nil
}
func requiredHTTPPath(raw json.RawMessage, path string) (json.RawMessage, error) {
	value, found, e := rawHTTPPath(raw, path)
	if e != nil || !found || bytes.Equal(value, []byte("null")) {
		return nil, authz.ErrDenied
	}
	return value, nil
}
func httpString(raw json.RawMessage) (string, error) {
	var s string
	if json.Unmarshal(raw, &s) != nil || s == "" || strings.TrimSpace(s) != s {
		return "", authz.ErrDenied
	}
	return s, nil
}
func httpID(raw json.RawMessage) (string, error) {
	if len(raw) > 0 && raw[0] == '"' {
		return httpString(raw)
	}
	var id authz.EntityID
	if id.UnmarshalJSON(raw) != nil {
		return "", authz.ErrDenied
	}
	return string(id), nil
}
func idAt(raw json.RawMessage, path string) (string, error) {
	v, e := requiredHTTPPath(raw, path)
	if e != nil {
		return "", e
	}
	return httpID(v)
}
func stringAt(raw json.RawMessage, path string) (string, error) {
	v, e := requiredHTTPPath(raw, path)
	if e != nil {
		return "", e
	}
	return httpString(v)
}
func stringsAt(raw json.RawMessage, path string) ([]string, error) {
	if path == "" {
		return nil, nil
	}
	v, e := requiredHTTPPath(raw, path)
	if e != nil {
		return nil, e
	}
	var values []string
	if json.Unmarshal(v, &values) != nil || values == nil {
		return nil, authz.ErrDenied
	}
	seen := map[string]bool{}
	for _, s := range values {
		if s == "" || strings.TrimSpace(s) != s || seen[s] {
			return nil, authz.ErrDenied
		}
		seen[s] = true
	}
	sort.Strings(values)
	return values, nil
}
func timeAt(raw json.RawMessage, path string) (time.Time, error) {
	v, e := requiredHTTPPath(raw, path)
	var t time.Time
	if e != nil || json.Unmarshal(v, &t) != nil || t.IsZero() {
		return time.Time{}, authz.ErrDenied
	}
	return t, nil
}
func hashHTTP(v any) string {
	b, _ := json.Marshal(v)
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}
func decodeHTTPBody(r *http.Response, max int64) (json.RawMessage, error) {
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		if r.StatusCode == 401 || r.StatusCode == 403 {
			return nil, authz.ErrDenied
		}
		return nil, authz.ErrUnavailable
	}
	b, e := io.ReadAll(io.LimitReader(r.Body, max+1))
	if e != nil || len(b) > int(max) || validateUniqueJSON(b) != nil {
		return nil, authz.ErrUnavailable
	}
	return b, nil
}
func deadlineHTTP(start, now, tokenExpiry time.Time, lease, skew time.Duration, raw json.RawMessage, evalPath, untilPath string, required bool) (time.Time, error) {
	return deadlineHTTPWithLimit(start, now, tokenExpiry, lease, skew, raw, evalPath, untilPath, required, 5*time.Minute)
}
func deadlineHTTPWithLimit(start, now, tokenExpiry time.Time, lease, skew time.Duration, raw json.RawMessage, evalPath, untilPath string, required bool, sourceMaximum time.Duration) (time.Time, error) {
	deadline := tokenExpiry
	cap := func(t time.Time) {
		if t.Before(deadline) {
			deadline = t
		}
	}
	cap(start.Add(lease))
	if evalPath != "" {
		_, hasEval, e := rawHTTPPath(raw, evalPath)
		if e != nil {
			return time.Time{}, e
		}
		_, hasUntil, e := rawHTTPPath(raw, untilPath)
		if e != nil || hasEval != hasUntil || required && !hasEval {
			return time.Time{}, authz.ErrDenied
		}
		if hasEval {
			evaluated, e := timeAt(raw, evalPath)
			if e != nil {
				return time.Time{}, e
			}
			until, e := timeAt(raw, untilPath)
			if e != nil || evaluated.After(now.Add(skew)) || !until.After(evaluated) || until.After(evaluated.Add(sourceMaximum)) {
				return time.Time{}, authz.ErrDenied
			}
			cap(until.Add(-skew))
			cap(evaluated.Add(lease).Add(-skew))
		}
	} else if required {
		return time.Time{}, authz.ErrDenied
	}
	if !deadline.After(now) {
		return time.Time{}, authz.ErrDenied
	}
	return deadline, nil
}
