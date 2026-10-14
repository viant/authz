package oauth

import (
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/viant/authz"
	"github.com/viant/authz/gating"
	"reflect"
)

func TestCloneHTTPProfileIsolatesMutableAuthorityAndProjection(t *testing.T) {
	original := httpProfile{principal: gating.Principal{Facts: authz.Facts{Subject: "owned", GrantedScopes: []string{"studio:read"}, Entities: []authz.Entity{{Type: "order", ID: "101"}}, EntityGroups: authz.EntityGroups{"order": []authz.EntityID{"101"}}, Roles: []string{"reader"}, Exposures: []string{"authoring"}, EntityPermissions: []authz.EntityPermission{{Type: "order", ID: "101", Permissions: []string{"read"}}}, ValidUntil: time.Now().Add(time.Minute)}, MembershipGroups: []string{"owned-group"}}, userID: "7", bearerHash: "opaque", projection: map[string]any{"account": json.Number("21"), "nested": map[string]any{"roles": []any{"reader"}}}}
	first, second := cloneHTTPProfile(original), cloneHTTPProfile(original)
	first.principal.Facts.GrantedScopes[0] = "studio:write"
	first.principal.Facts.Entities[0].ID = "999"
	first.principal.Facts.EntityGroups["order"][0] = "999"
	first.principal.Facts.EntityGroups["other"] = []authz.EntityID{"999"}
	first.principal.Facts.Roles[0] = "owner"
	first.principal.Facts.Exposures[0] = "other-feature"
	first.principal.Facts.EntityPermissions[0].Permissions[0] = "write"
	first.principal.MembershipGroups[0] = "other-group"
	first.projection["account"] = json.Number("99")
	first.projection["nested"].(map[string]any)["roles"].([]any)[0] = "owner"
	for _, profile := range []httpProfile{original, second} {
		assertProfileCloneEqual(t, []string{"studio:read"}, profile.principal.Facts.GrantedScopes)
		assertProfileCloneEqual(t, []authz.Entity{{Type: "order", ID: "101"}}, profile.principal.Facts.Entities)
		assertProfileCloneEqual(t, authz.EntityGroups{"order": []authz.EntityID{"101"}}, profile.principal.Facts.EntityGroups)
		assertProfileCloneEqual(t, "reader", profile.principal.Facts.Roles[0])
		assertProfileCloneEqual(t, "authoring", profile.principal.Facts.Exposures[0])
		assertProfileCloneEqual(t, "read", profile.principal.Facts.EntityPermissions[0].Permissions[0])
		assertProfileCloneEqual(t, "owned-group", profile.principal.MembershipGroups[0])
		assertProfileCloneEqual(t, json.Number("21"), profile.projection["account"])
		assertProfileCloneEqual(t, "reader", profile.projection["nested"].(map[string]any)["roles"].([]any)[0])
		assertProfileCloneEqual(t, "opaque", profile.bearerHash)
	}
}

func TestCloneHTTPProfileConcurrentRequestIsolation(t *testing.T) {
	original := httpProfile{principal: gating.Principal{Facts: authz.Facts{Roles: []string{"reader"}}}, projection: map[string]any{"account": json.Number("21")}}
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			profile := cloneHTTPProfile(original)
			profile.principal.Facts.Roles[0] = "request-local"
			profile.projection["account"] = json.Number("99")
		}()
	}
	workers.Wait()
	assertProfileCloneEqual(t, "reader", original.principal.Facts.Roles[0])
	assertProfileCloneEqual(t, json.Number("21"), original.projection["account"])
}

func assertProfileCloneEqual(t *testing.T, expected, actual any) {
	t.Helper()
	if !reflect.DeepEqual(expected, actual) {
		t.Fatalf("expected %v; got %v", expected, actual)
	}
}

func TestCloneHTTPProfilePreservesAbsentAuthorityCollections(t *testing.T) {
	original := httpProfile{}
	cloned := cloneHTTPProfile(original)
	assertProfileCloneEqual(t, original, cloned)
}
