package reader

// Output is the generated output scaffold for policy.
type Output struct {
	Policies []*ResourcePolicy `parameter:"Policies,kind=output,in=view,dataType=[]*ResourcePolicy" view:"policy,type=ResourcePolicy,table=resource_policy_heads" sql:"uri=datly_policy_reader_policy:sql/policy.sql"`
}
