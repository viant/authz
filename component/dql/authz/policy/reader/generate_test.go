package reader_test

//go:generate env DATLY_GENERATE_POLICY_READER=1 go test -run TestGeneratePolicyReader -count=1 .

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/viant/authz/component/schema"
	"github.com/viant/bindly/resource"
	"github.com/viant/datly/transcribe"
	"github.com/viant/datly/transcribe/column"
	_ "modernc.org/sqlite"
)

func TestGeneratePolicyReader(t *testing.T) {
	ctx := context.Background()
	db, err := sql.Open("sqlite", "file:"+filepath.Join(t.TempDir(), "studio.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	migration, err := schema.New("sqlite")
	if err != nil {
		t.Fatal(err)
	}
	if err := migration.Up(ctx, db); err != nil {
		t.Fatal(err)
	}
	root, err := filepath.Abs("../../../../")
	if err != nil {
		t.Fatal(err)
	}
	directory := filepath.Join(root, "dql/authz/policy/reader")
	payload, err := os.ReadFile(filepath.Join(directory, "policy.dql"))
	if err != nil {
		t.Fatal(err)
	}
	resources, err := resource.New().WithDefault(os.DirFS(directory))
	if err != nil {
		t.Fatal(err)
	}
	compiled, err := transcribe.NewCompiler().Compile(ctx, &transcribe.Source{
		Scope: "github.com/viant/authz/component/dql/authz/policy/reader",
		Name:  "policy", Path: "policy.dql", Text: string(payload), Connector: "authz",
		Resources: resources, ColumnRefiner: column.New(column.Connections{"authz": db}),
	})
	if err != nil {
		t.Fatal(err)
	}
	destination := t.TempDir()
	if os.Getenv("DATLY_GENERATE_POLICY_READER") == "1" {
		destination = root
	} else if err := os.WriteFile(filepath.Join(destination, "go.mod"), []byte("module github.com/viant/authz/component\n\ngo 1.25.8\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (transcribe.Generator{Operation: "get"}).Generate(ctx,
		transcribe.GenerationRequest{Compiled: compiled, Destination: destination}); err != nil {
		t.Fatal(err)
	}
	// The compiler expands the view projection with SQLite double-quoted
	// identifiers. These schema identifiers need no quotes, and the same
	// generated resource is executed against both SQLite and MySQL.
	sqlPath := filepath.Join(destination, "policy", "reader", "sql", "policy.sql")
	sqlText, err := os.ReadFile(sqlPath)
	if err != nil {
		t.Fatal(err)
	}
	portable := regexp.MustCompile(`resource_policy\."([a-z_]+)"`).ReplaceAllString(string(sqlText), `resource_policy.$1`)
	if err := os.WriteFile(sqlPath, []byte(portable), 0o644); err != nil {
		t.Fatal(err)
	}
}
