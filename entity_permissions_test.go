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

func TestPermissionIndexIsNarrowedAndLookupFriendly(t *testing.T) {
	grants := []EntityPermission{{Type: "advertiser", ID: "123", Permissions: []string{"read", "edit"}}, {Type: "advertiser", ID: "456", Permissions: []string{"admin", "read"}}, {Type: "publisher", ID: "127", Permissions: []string{"read"}}}
	index, err := IndexEntityPermissions(grants, Decision{Bounded: true, Entities: []Entity{{Type: "advertiser", ID: "123"}}})
	if err != nil {
		t.Fatal(err)
	}
	if len(index) != 1 || len(index["advertiser"]["read"]) != 1 || index["advertiser"]["read"][0] != "123" || len(index["advertiser"]["admin"]) != 0 {
		t.Fatal("permission index widened decision", index)
	}
	grants[0].ID = "tampered"
	grants[0].Permissions[0] = "changed"
	if index["advertiser"]["read"][0] != "123" {
		t.Fatal("index shares provider storage")
	}
	if _, err = IndexEntityPermissions(grants, Decision{}); err == nil {
		t.Fatal("unbounded decision accepted")
	}
}
