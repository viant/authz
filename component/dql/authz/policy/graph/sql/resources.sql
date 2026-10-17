SELECT DISTINCT h.tenant_id,h.resource_kind,h.resource_id
FROM resource_policies h
${predicate.Builder().CombineAnd($predicate.FilterGroup(0, "AND")).Build("WHERE")}
