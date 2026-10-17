SELECT * FROM (SELECT h.tenant_id,h.resource_kind,h.resource_id,h.resource_version,h.revision
FROM resource_policies h
${predicate.Builder().CombineAnd($predicate.FilterGroup(0, "AND")).Build("WHERE")}
) revisions