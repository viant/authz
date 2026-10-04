// Command authz hosts the Datly SDK components over HTTP and MCP.
package main

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	_ "github.com/go-sql-driver/mysql"
	jwtlib "github.com/golang-jwt/jwt/v5"
	"github.com/viant/authz"
	"github.com/viant/authz/component/api"
	gatesql "github.com/viant/authz/component/gate/sqlstore"
	"github.com/viant/authz/component/schema"
	policystore "github.com/viant/authz/component/store/sql"
	"github.com/viant/authz/gating"
	"github.com/viant/authz/oauth"
	gateway "github.com/viant/datly/gateway/http"
	"github.com/viant/datly/mcp"
	mcpserver "github.com/viant/datly/mcp/server"
	druntime "github.com/viant/datly/runtime"
	nativeauth "github.com/viant/datly/runtime/auth"
	"github.com/viant/datly/runtime/registry"
	"github.com/viant/mcp-protocol/authorization"
	"github.com/viant/mcp-protocol/oauth2/meta"
	mcpschema "github.com/viant/mcp-protocol/schema"
	"github.com/viant/scy"
	"github.com/viant/scy/auth/jwt/verifier"
	_ "modernc.org/sqlite"
)

func main() {
	if err := run(); err != nil {
		log.Fatal(err)
	}
}
func run() error {
	driver := flag.String("driver", "sqlite", "sqlite or mysql")
	base := flag.String("base-dir", "", "optional authz/component source module directory for source-validated registration")
	address := flag.String("http", "127.0.0.1:8085", "HTTP SDK listener")
	mcpAddress := flag.String("mcp", "127.0.0.1:8095", "MCP listener")
	issuer := flag.String("issuer", "", "trusted fact-token issuer")
	audience := flag.String("audience", "", "trusted fact-token audience")
	keyFile := flag.String("public-key", "", "trusted RSA public key PEM file")
	editors := flag.String("policy-editor-roles", os.Getenv("AUTHZ_POLICY_EDITOR_ROLES"), "predefined roles for policy creation and editor-roles replacement; empty denies those writes")
	policyReplacement := flag.String("policy-replace-rule", "editor-roles", "policy replacement authority: editor-roles or manage-access; creation always uses policy-editor-roles")
	requirementsFile := flag.String("gate-requirements", "", "trusted JSON file of exact, versioned gate requirement bindings (read only)")
	gateStoreDir := flag.String("gate-store-dir", "", "single-process durable gate revision directory; requires -gate-requirements")
	gateSQLStore := flag.Bool("gate-sql-store", false, "transactional gate revisions in AUTHZ_DB_DSN; requires -gate-requirements")
	gateChoicesFile := flag.String("gate-choices", "", "trusted exact resource/action editor choices JSON file; requires -gate-requirements")
	flag.Parse()
	if *gateStoreDir != "" && *requirementsFile == "" {
		return fmt.Errorf("gate-store-dir requires gate-requirements")
	}
	if *gateSQLStore && *requirementsFile == "" {
		return fmt.Errorf("gate-sql-store requires gate-requirements")
	}
	if *gateSQLStore && *gateStoreDir != "" {
		return fmt.Errorf("gate-sql-store and gate-store-dir are mutually exclusive")
	}
	if *gateChoicesFile != "" && *requirementsFile == "" {
		return fmt.Errorf("gate-choices requires gate-requirements")
	}
	if *policyReplacement != "editor-roles" && *policyReplacement != "manage-access" {
		return fmt.Errorf("policy-replace-rule must be editor-roles or manage-access")
	}
	if *issuer == "" || *audience == "" || *keyFile == "" {
		return fmt.Errorf("issuer, audience and public-key are required")
	}
	pem, err := os.ReadFile(*keyFile)
	if err != nil {
		return fmt.Errorf("read verifier public key: %w", err)
	}
	key, err := jwtlib.ParseRSAPublicKeyFromPEM(pem)
	if err != nil {
		return fmt.Errorf("parse verifier public key: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	migration, err := schema.New(*driver)
	if err != nil {
		return err
	}
	dsn := os.Getenv("AUTHZ_DB_DSN")
	if dsn == "" {
		if *driver != "sqlite" {
			return fmt.Errorf("AUTHZ_DB_DSN required for mysql")
		}
		if err = os.MkdirAll(".data", 0700); err != nil {
			return err
		}
		dsn = "file:" + filepath.Join(".data", "authz.db") + "?cache=shared"
	}
	db, err := sql.Open(*driver, dsn)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(8)
	if err = db.PingContext(ctx); err != nil {
		return fmt.Errorf("connect policy database: %w", err)
	}
	if err = migration.Up(ctx, db); err != nil {
		return err
	}
	store := &policystore.Store{DB: db}
	defer store.Close(context.Background())
	provider, err := tokenProvider(*issuer, *audience, key)
	if err != nil {
		return err
	}
	roles := []string{}
	if strings.TrimSpace(*editors) != "" {
		for _, role := range strings.Split(*editors, ",") {
			roles = append(roles, strings.TrimSpace(role))
		}
	}
	services := &api.Services{Authorization: &authz.Service{Store: store, Provider: provider}, Policies: &authz.Administration{Store: store, Provider: provider, EditorRoles: roles}}
	if *policyReplacement == "manage-access" {
		services.Policies.Management = services.Authorization
	}
	if *requirementsFile != "" {
		bindings, err := readRequirementBindings(*requirementsFile)
		if err != nil {
			return err
		}
		var requirements gating.RequirementsStore
		var writer gating.RequirementsWriter
		if *gateSQLStore {
			persisted, err := gatesql.New(ctx, db, bindings)
			if err != nil {
				return fmt.Errorf("gate requirements: %w", err)
			}
			requirements, writer = persisted, persisted
		} else if *gateStoreDir != "" {
			persisted, err := gating.NewFileStore(*gateStoreDir, bindings)
			if err != nil {
				return fmt.Errorf("gate requirements: %w", err)
			}
			requirements, writer = persisted, persisted
		} else {
			static, err := gating.NewStaticStore(bindings)
			if err != nil {
				return fmt.Errorf("gate requirements: %w", err)
			}
			requirements = static
		}
		services.Gates = &gating.Evaluator{ACL: services.Authorization, Principals: provider, Requirements: requirements, Entities: &oauth.FactEntityPermissionProvider{Principals: provider}}
		services.Requirements = &gating.Administration{ACL: services.Authorization, Store: requirements, Writer: writer}
		if *gateChoicesFile != "" {
			choiceBindings, err := readChoiceBindings(*gateChoicesFile)
			if err != nil {
				return err
			}
			choices, err := gating.NewStaticChoices(choiceBindings)
			if err != nil {
				return fmt.Errorf("gate choices: %w", err)
			}
			if err := validateChoiceCoverage(bindings, choiceBindings); err != nil {
				return err
			}
			services.Requirements.Choices = choices
		}
	}
	codecs, err := nativeauth.New(ctx, &nativeauth.Config{JWTValidator: &verifier.Config{RSA: []*scy.Resource{{URL: "authz-public-key", Data: pem}}}})
	if err != nil {
		return err
	}
	var components []*registry.RegisteredComponent
	if *base == "" {
		components, err = api.LinkedRegistrations(services, codecs)
	} else {
		components, err = api.Registrations(ctx, *base, services, codecs)
	}
	if err != nil {
		return err
	}
	runtime, err := druntime.NewRuntime(components, druntime.WithExposedPackages([]string{api.Package}, nil))
	if err != nil {
		return err
	}
	defer runtime.Shutdown(context.Background())
	handler, err := (gateway.Config{}).NewHandler(runtime, nil, "1")
	if err != nil {
		return err
	}
	httpServer := &http.Server{Addr: *address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 2 * time.Minute}
	catalog, err := mcp.New(mcp.Config{Components: components, Invoker: runtime, Authorization: &authorization.Policy{Global: &authorization.Authorization{ProtectedResourceMetadata: &meta.ProtectedResourceMetadata{Resource: "http://" + *mcpAddress + "/mcp"}}}})
	if err != nil {
		return err
	}
	protocol, err := mcpserver.New(mcpserver.Config{Service: catalog, Implementation: mcpschema.Implementation{Name: "authz", Version: "1"}, Transport: mcpserver.TransportConfig{Kind: mcpserver.TransportStreamable, Address: *mcpAddress}})
	if err != nil {
		return err
	}
	mcpHTTP, err := protocol.HTTP()
	if err != nil {
		return err
	}
	failures := make(chan error, 2)
	go func() { failures <- httpServer.ListenAndServe() }()
	go func() { failures <- mcpHTTP.ListenAndServe() }()
	log.Printf("authz HTTP=%s MCP=%s database=%s policy-editor-roles=%d", *address, *mcpAddress, *driver, len(roles))
	select {
	case <-ctx.Done():
	case err = <-failures:
		if err != nil && err != http.ErrServerClosed {
			stop()
		}
	}
	closeCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = httpServer.Shutdown(closeCtx)
	_ = mcpHTTP.Shutdown(closeCtx)
	if err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}
func tokenProvider(issuer, audience string, key *rsa.PublicKey) (*oauth.Provider, error) {
	return oauth.New(oauth.Config{Issuer: issuer, Audience: audience, Algorithms: []string{"RS256"}, Keyfunc: func(*jwtlib.Token) (any, error) { return key, nil }})
}

func readRequirementBindings(path string) ([]gating.Binding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open gate requirements: %w", err)
	}
	defer file.Close()
	var bindings []gating.Binding
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bindings); err != nil {
		return nil, fmt.Errorf("decode gate requirements: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("gate requirements must contain one JSON array")
	}
	return bindings, nil
}

func readChoiceBindings(path string) ([]gating.ChoiceBinding, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open gate choices: %w", err)
	}
	defer file.Close()
	var bindings []gating.ChoiceBinding
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&bindings); err != nil {
		return nil, fmt.Errorf("decode gate choices: %w", err)
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return nil, fmt.Errorf("gate choices must contain one JSON array")
	}
	return bindings, nil
}

func validateChoiceCoverage(requirements []gating.Binding, choices []gating.ChoiceBinding) error {
	type key struct {
		resource authz.Resource
		action   string
	}
	needed := make(map[key]bool, len(requirements))
	for _, binding := range requirements {
		needed[key{binding.Resource, binding.Action}] = true
	}
	for _, binding := range choices {
		candidate := key{binding.Resource, binding.Action}
		if !needed[candidate] {
			return fmt.Errorf("gate choices have no matching requirement binding")
		}
		delete(needed, candidate)
	}
	if len(needed) != 0 {
		return fmt.Errorf("gate requirements are missing editor choices")
	}
	return nil
}
