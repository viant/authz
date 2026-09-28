package authz

import (
	"encoding/json"
	"testing"
)

func TestEntityPermissionsAreAListAndNeverImplyGlobalOrHierarchicalAccess(t *testing.T) {
	var grants []EntityPermission
	if err := json.Unmarshal([]byte(`[{"type":"advertiser","id":9007199254740993,"permissions":["read"]},{"type":"advertiser","id":"456","permissions":["read","edit"]}]`), &grants); err != nil {
		t.Fatal(err)
	}
	if grants[0].ID != "9007199254740993" || !HasPermission(grants, "advertiser", "456", "edit") {
		t.Fatal("exact list grant was lost")
	}
	for _, check := range []struct {
		kind       string
		id         EntityID
		permission string
	}{{"advertiser", "9007199254740993", "edit"}, {"publisher", "456", "edit"}, {"advertiser", "child-of-456", "read"}, {"advertiser", "other", "admin"}} {
		if HasPermission(grants, check.kind, check.id, check.permission) {
			t.Fatal("entity permission widened")
		}
	}
}
