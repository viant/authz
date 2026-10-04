package permissions

import (
	"github.com/viant/authz"
	"reflect"
	"testing"
)

func TestStructQLPermissionProjectionRemainsNarrowed(t *testing.T) {
	grants := []authz.EntityPermission{{Type: "advertiser", ID: "123", Permissions: []string{"read", "edit"}}, {Type: "advertiser", ID: "456", Permissions: []string{"admin", "read"}}}
	index, err := Index(grants, authz.Decision{Bounded: true, Entities: []authz.Entity{{Type: "advertiser", ID: "123"}}})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(index["advertiser"]["read"], []string{"123"}) || !reflect.DeepEqual(index["advertiser"]["edit"], []string{"123"}) || len(index["advertiser"]["admin"]) != 0 {
		t.Fatal("StructQL widened permission view", index)
	}
}
