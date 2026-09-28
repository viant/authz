package access

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/go-sql-driver/mysql"
	"github.com/viant/authz"
	"github.com/viant/authz/datly/schema"
	"os"
	"testing"
	"time"
)

func TestMySQLPolicyStorage(t *testing.T) {
	dsn := os.Getenv("AUTHZ_MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("AUTHZ_MYSQL_TEST_DSN must point to an authorized local MySQL test server")
	}
	config, err := mysql.ParseDSN(dsn)
	if err != nil {
		t.Fatal("invalid MySQL test configuration")
	}
	config.DBName = ""
	config.ParseTime = true
	admin, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	name := fmt.Sprintf("authz_test_%d", time.Now().UnixNano())
	if _, err = admin.Exec("CREATE DATABASE `" + name + "` CHARACTER SET utf8mb4"); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, dropErr := admin.Exec("DROP DATABASE IF EXISTS `" + name + "`"); dropErr != nil {
			t.Errorf("remove isolated MySQL database: %v", dropErr)
		}
	}()
	config.DBName = name
	db, err := sql.Open("mysql", config.FormatDSN())
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	migration, _ := schema.New("mysql")
	if err = migration.Up(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	if err = migration.Up(context.Background(), db); err != nil {
		t.Fatal("schema must be idempotent", err)
	}
	store := &Store{DB: db}
	defer store.Close(context.Background())
	resource := authz.Resource{Kind: "tool", ID: "forecasting", Version: "1", Tenant: "one"}
	initial := authz.Document{Resource: resource, Policies: map[string]authz.Policy{"execute": {Mode: "protected", Rule: &authz.Rule{Kind: "role", Value: "reader"}, EntityType: "publisher"}}}
	first, err := store.Create(context.Background(), initial, "admin")
	if err != nil || first.Revision != 1 {
		t.Fatalf("create: %+v %v", first, err)
	}
	if _, err = store.Create(context.Background(), initial, "duplicate"); !errors.Is(err, authz.ErrConflict) {
		t.Fatalf("duplicate: %v", err)
	}
	second, err := store.Replace(context.Background(), first, 1, "editor")
	if err != nil || second.Revision != 2 {
		t.Fatalf("replace: %+v %v", second, err)
	}
	if _, err = store.Replace(context.Background(), first, 1, "stale"); !errors.Is(err, authz.ErrConflict) {
		t.Fatalf("stale: %v", err)
	}
	loaded, err := store.Get(context.Background(), resource)
	if err != nil || loaded.Revision != 2 || loaded.Policies["execute"].EntityType != "publisher" {
		t.Fatalf("read: %+v %v", loaded, err)
	}
	var history int
	if err = db.QueryRow("SELECT COUNT(*) FROM resource_policy_revisions").Scan(&history); err != nil || history != 2 {
		t.Fatalf("history=%d err=%v", history, err)
	}
	var actor string
	if err = db.QueryRow("SELECT actor_id FROM resource_policy_revisions WHERE revision=2").Scan(&actor); err != nil || actor != "editor" {
		t.Fatalf("audit actor=%q err=%v", actor, err)
	}
	for _, other := range []authz.Resource{{Kind: "skill", ID: resource.ID, Version: "1", Tenant: "one"}, {Kind: resource.Kind, ID: resource.ID, Version: "2", Tenant: "one"}, {Kind: resource.Kind, ID: resource.ID, Version: "1", Tenant: "two"}} {
		if _, err = store.Get(context.Background(), other); !errors.Is(err, sql.ErrNoRows) {
			t.Fatal("resource isolation failed", err)
		}
	}
	if _, err = db.Exec("CREATE TRIGGER reject_authz_history BEFORE INSERT ON resource_policy_revisions FOR EACH ROW SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT='fixture history failure'"); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Replace(context.Background(), second, 2, "rollback"); err == nil {
		t.Fatal("history failure accepted")
	}
	loaded, err = store.Get(context.Background(), resource)
	if err != nil || loaded.Revision != 2 {
		t.Fatalf("head was not rolled back: %+v %v", loaded, err)
	}
}
