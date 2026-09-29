package reader

import (
	embed "embed"
	xdatly "github.com/viant/xdatly"
	reflect "reflect"
)

func init() {}

// Component is the generated component scaffold for policy.
type PolicyComponent struct {
	Contract xdatly.Component[Input, Output] "component:\"policy,path=/_authz/policy-store/read,method=GET,connector=authz,view=policy,internal=true\" routeName:\"policy\" caseFormat:\"lc\""
}

// PolicyDatlyType returns the public component type.
func PolicyDatlyType() reflect.Type { return reflect.TypeOf((*PolicyComponent)(nil)).Elem() }

// The package-level value keeps this real component type reachable for runtime discovery.
var PolicyDatly = new(PolicyComponent)
var _datlyReachablePolicyComponent = reflect.TypeFor[PolicyComponent]()

func (PolicyComponent) EmbedFS() *embed.FS {
	return &PolicyDatlyResources
}

func (PolicyComponent) EmbedNamespace() string {
	return PolicyDatlyResourceNamespace
}
