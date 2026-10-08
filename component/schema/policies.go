package schema

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
)

func policyDriver(driver string) (string, error) {
	m, err := New(driver)
	if err != nil {
		return "", err
	}
	return m.driver, nil
}

// PolicyDDL returns the canonical fresh DDL for the universal policy head and
// immutable revision tables. It contains no application-specific namespace
// columns, upgrade ledger, or legacy table conversion.
func PolicyDDL(driver string) (string, error) {
	driver, err := policyDriver(driver)
	if err != nil {
		return "", err
	}
	raw, err := files.ReadFile(driver + ".sql")
	if err != nil {
		return "", err
	}
	var result []string
	for _, statement := range strings.Split(string(raw), ";") {
		statement = strings.TrimSpace(statement)
		if strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS resource_policies (") || strings.HasPrefix(statement, "CREATE TABLE IF NOT EXISTS resource_policy_revisions (") {
			result = append(result, statement+";")
		}
	}
	if len(result) != 2 {
		return "", fmt.Errorf("canonical policy schema inventory is invalid")
	}
	return strings.Join(result, "\n\n"), nil
}

// CreatePolicies installs the canonical policy tables on a fresh database.
// It is idempotent for tables already created from the same DDL; it never
// renames, alters, backfills, or converts an existing schema.
func CreatePolicies(ctx context.Context, db *sql.DB, driver string) error {
	m, err := New(driver)
	if err != nil {
		return err
	}
	return m.CreatePolicies(ctx, db)
}

// CreatePolicies installs the two canonical policy tables for this driver.
func (m *Migration) CreatePolicies(ctx context.Context, db *sql.DB) error {
	if m == nil || db == nil {
		return fmt.Errorf("policy schema database is required")
	}
	ddl, err := PolicyDDL(m.driver)
	if err != nil {
		return err
	}
	for _, statement := range strings.Split(ddl, ";") {
		if strings.TrimSpace(statement) == "" {
			continue
		}
		if _, err := db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("create policy tables: %w", err)
		}
	}
	return nil
}

// PolicyColumnDefinition returns the canonical fresh-table definition for a
// shared policy column. It is used by consumers that compose or inspect DDL.
func PolicyColumnDefinition(driver, table, column string) (string, error) {
	if table != "resource_policies" && table != "resource_policy_revisions" {
		return "", fmt.Errorf("not a shared policy table")
	}
	ddl, err := PolicyDDL(driver)
	if err != nil {
		return "", err
	}
	start := strings.Index(ddl, "CREATE TABLE IF NOT EXISTS "+table+" (")
	if start < 0 {
		return "", fmt.Errorf("policy table missing")
	}
	body := ddl[start:]
	end := strings.Index(body, "\n)")
	if end < 0 {
		return "", fmt.Errorf("policy table definition invalid")
	}
	for _, line := range strings.Split(body[:end], "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ","))
		fields := strings.Fields(line)
		if len(fields) > 1 && fields[0] == column {
			return line, nil
		}
	}
	return "", fmt.Errorf("shared policy column %s.%s missing", table, column)
}
