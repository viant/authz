package oauth

import "testing"

func TestAuthorityRejectsDuplicateJSONKeys(t *testing.T) {
	for _, body := range []string{`{"info":{"subject":"alice","subject":"bob"}}`, `{"info":{"results":[{"permissions":{"read":false,"read":true}}]}}`, `{} {}`, `{"a":[{"x":1,"x":2}]}`} {
		if validateUniqueJSON([]byte(body)) == nil {
			t.Fatalf("ambiguous authority accepted: %s", body)
		}
	}
	if err := validateUniqueJSON([]byte(`{"info":{"results":[{"permissions":{"read":false}}]}}`)); err != nil {
		t.Fatal(err)
	}
}
