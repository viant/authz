// Command authz hosts the Datly SDK components over HTTP and MCP.
package main

import (
	"context"
	"crypto/rsa"
	"database/sql"
	"flag"
	"fmt"
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
	"github.com/viant/authz/datly/api"
	"github.com/viant/authz/datly/schema"
	policystore "github.com/viant/authz/datly/store/sql"
	"github.com/viant/authz/oauth"
	gateway "github.com/viant/datly/gateway/http"
	"github.com/viant/datly/mcp"
	mcpserver "github.com/viant/datly/mcp/server"
	druntime "github.com/viant/datly/runtime"
	nativeauth "github.com/viant/datly/runtime/auth"
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
	base := flag.String("base-dir", ".", "authz/datly source module directory")
	address := flag.String("http", "127.0.0.1:8085", "HTTP SDK listener")
	mcpAddress := flag.String("mcp", "127.0.0.1:8095", "MCP listener")
	issuer := flag.String("issuer", "", "trusted fact-token issuer")
	audience := flag.String("audience", "", "trusted fact-token audience")
	keyFile := flag.String("public-key", "", "trusted RSA public key PEM file")
	editors := flag.String("policy-editor-roles", os.Getenv("AUTHZ_POLICY_EDITOR_ROLES"), "predefined roles allowed to create/modify policies; empty denies writes")
	flag.Parse()
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
	codecs, err := nativeauth.New(ctx, &nativeauth.Config{JWTValidator: &verifier.Config{RSA: []*scy.Resource{{URL: "authz-public-key", Data: pem}}}})
	if err != nil {
		return err
	}
	components, err := api.Registrations(ctx, *base, services, codecs)
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
func tokenProvider(issuer, audience string, key *rsa.PublicKey) (authz.Provider, error) {
	return oauth.New(oauth.Config{Issuer: issuer, Audience: audience, Algorithms: []string{"RS256"}, Keyfunc: func(*jwtlib.Token) (any, error) { return key, nil }})
}
