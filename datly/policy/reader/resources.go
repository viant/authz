package reader

import "embed"

// DatlyResourceNamespace identifies this package's generated resource filesystem.
const PolicyDatlyResourceNamespace = "authz_policy_reader_policy"

//go:embed "sql/policy.sql"
var PolicyDatlyResources embed.FS
