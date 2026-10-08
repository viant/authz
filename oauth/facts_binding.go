package oauth

import (
	"reflect"

	"github.com/viant/authz"
)

func sameVerifiedAccountFacts(a, b authz.Facts) bool {
	return a.Subject == b.Subject && a.Issuer == b.Issuer && a.Tenant == b.Tenant &&
		reflect.DeepEqual(a.Roles, b.Roles) && reflect.DeepEqual(a.Exposures, b.Exposures) &&
		reflect.DeepEqual(a.EntityGroups, b.EntityGroups) && reflect.DeepEqual(a.Entities, b.Entities) &&
		reflect.DeepEqual(a.EntityPermissions, b.EntityPermissions) && reflect.DeepEqual(a.GrantedScopes, b.GrantedScopes)
}
