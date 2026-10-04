// Package api declares Datly 1.0 components that are the authz SDK endpoints.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"github.com/viant/authz"
	"github.com/viant/authz/gating"
	"github.com/viant/authz/oauth"
	rhandler "github.com/viant/datly/runtime/handler"
	"github.com/viant/datly/runtime/handler/custom"
	"github.com/viant/scy/auth/jwt"
	"github.com/viant/xdatly"
	xhandler "github.com/viant/xdatly/handler"
	xresponse "github.com/viant/xdatly/response"
	"reflect"
	"strings"
)

const Capability = xhandler.ValueKey("authz.sdk")
const Package = "github.com/viant/authz/component/api"

type Services struct {
	Authorization    *authz.Service
	Policies         *authz.Administration
	Gates            *gating.Evaluator
	Requirements     *gating.Administration
	Catalog          CatalogProvider
	CatalogAdmission CatalogAdmission
}

// CatalogEntry is a host-authored resource and action choice. The SDK checks
// viewAccess before returning it; the entry itself is never a grant.
type CatalogEntry struct {
	Name        string         `json:"name"`
	Resource    authz.Resource `json:"resource"`
	Actions     []string       `json:"actions"`
	GateActions []string       `json:"gateActions,omitempty"`
	// Target is an optional server-authored selection hint for a host editor.
	// It conveys no identity or allow decision; the target service reauthorizes.
	Target map[string]string `json:"target,omitempty"`
	// Context is supplied by the trusted catalog provider for an optional
	// host admission check. It is never serialized to HTTP/MCP clients.
	Context any `json:"-"`
}

// CatalogAdmission may handle a host-owned entry whose authority is not a
// standalone ACL document (for example an inherited logical resource).
// Unhandled entries keep the ordinary shared viewAccess policy check.
type CatalogAdmission func(context.Context, gating.Principal, CatalogEntry) (handled bool, allowed bool, err error)

type CatalogProvider interface {
	List(context.Context) ([]CatalogEntry, error)
}

type CatalogFunc func(context.Context) ([]CatalogEntry, error)

func (f CatalogFunc) List(ctx context.Context) ([]CatalogEntry, error) { return f(ctx) }

type CatalogInput struct {
	JWT *jwt.Claims `parameter:"JWT,kind=header,in=Authorization,dataType=string" codec:"JwtClaim" json:"-"`
}

type CatalogOutput struct {
	Resources []CatalogEntry `json:"resources"`
}

type GateCheckInput struct {
	JWT      *jwt.Claims    `parameter:"JWT,kind=header,in=Authorization,dataType=string" codec:"JwtClaim" json:"-"`
	Resource authz.Resource `parameter:"Resource,kind=body,in=resource,required=true" json:"resource"`
	Action   string         `parameter:"Action,kind=body,in=action,required=true" json:"action"`
	Selected []authz.Entity `parameter:"Selected,kind=body,in=selected" json:"selected,omitempty"`
}
type GateInput struct {
	JWT      *jwt.Claims    `parameter:"JWT,kind=header,in=Authorization,dataType=string" codec:"JwtClaim" json:"-"`
	Resource authz.Resource `parameter:"Resource,kind=body,in=resource,required=true" json:"resource"`
	Action   string         `parameter:"Action,kind=body,in=action,required=true" json:"action"`
}
type GateWriteInput struct {
	JWT              *jwt.Claims         `parameter:"JWT,kind=header,in=Authorization,dataType=string" codec:"JwtClaim" json:"-"`
	Resource         authz.Resource      `parameter:"Resource,kind=body,in=resource,required=true" json:"resource"`
	Action           string              `parameter:"Action,kind=body,in=action,required=true" json:"action"`
	ExpectedRevision string              `parameter:"ExpectedRevision,kind=body,in=expectedRevision,required=true" json:"expectedRevision"`
	Requirements     gating.Requirements `parameter:"Requirements,kind=body,in=requirements,required=true" json:"requirements"`
}
type GateDecisionOutput struct {
	Decision gating.Decision `json:"decision"`
}
type GateDocumentOutput struct {
	Document gating.RequirementsDocument `json:"document"`
}
type GateContextOutput struct {
	Context gating.EditorContext `json:"context"`
}
type CheckInput struct {
	JWT       *jwt.Claims     `parameter:"JWT,kind=header,in=Authorization,dataType=string" codec:"JwtClaim" json:"-"`
	Resource  authz.Resource  `parameter:"Resource,kind=body,in=resource,required=true" json:"resource"`
	Action    string          `parameter:"Action,kind=body,in=action,required=true" json:"action"`
	Selection *[]authz.Entity `parameter:"Selection,kind=body,in=selection" json:"selection,omitempty"`
}
type PolicyInput struct {
	JWT      *jwt.Claims    `parameter:"JWT,kind=header,in=Authorization,dataType=string" codec:"JwtClaim" json:"-"`
	Resource authz.Resource `parameter:"Resource,kind=body,in=resource,required=true" json:"resource"`
}
type WriteInput struct {
	JWT      *jwt.Claims    `parameter:"JWT,kind=header,in=Authorization,dataType=string" codec:"JwtClaim" json:"-"`
	Document authz.Document `parameter:"Document,kind=body,in=document,required=true" json:"document"`
}
type DecisionOutput struct {
	Decision authz.Decision `json:"decision"`
}
type PolicyOutput struct {
	Document authz.Document `json:"document"`
}
type PolicyContextOutput struct {
	Context authz.EditorContext `json:"context"`
}
type Components struct {
	Catalog     xdatly.Component[CatalogInput, CatalogOutput]        `component:"catalog_list,path=/v1/authz/sdk/catalog.list,method=POST,handler=NewCatalog" mcp:"[{\"kind\":\"tool\",\"name\":\"authz.sdk.catalog.list\"}]"`
	Check       xdatly.Component[CheckInput, DecisionOutput]         `component:"check,path=/v1/authz/sdk/authorization.check,method=POST,handler=NewCheck" mcp:"[{\"kind\":\"tool\",\"name\":\"authz.sdk.authorization.check\"}]"`
	Get         xdatly.Component[PolicyInput, PolicyOutput]          `component:"policy_get,path=/v1/authz/sdk/policies.get,method=POST,handler=NewGet" mcp:"[{\"kind\":\"tool\",\"name\":\"authz.sdk.policies.get\"}]"`
	Context     xdatly.Component[PolicyInput, PolicyContextOutput]   `component:"policy_context,path=/v1/authz/sdk/policies.context,method=POST,handler=NewPolicyContext" mcp:"[{\"kind\":\"tool\",\"name\":\"authz.sdk.policies.context\"}]"`
	Create      xdatly.Component[WriteInput, PolicyOutput]           `component:"policy_create,path=/v1/authz/sdk/policies.create,method=POST,handler=NewCreate" mcp:"[{\"kind\":\"tool\",\"name\":\"authz.sdk.policies.create\"}]"`
	Replace     xdatly.Component[WriteInput, PolicyOutput]           `component:"policy_replace,path=/v1/authz/sdk/policies.replace,method=POST,handler=NewReplace" mcp:"[{\"kind\":\"tool\",\"name\":\"authz.sdk.policies.replace\"}]"`
	GateCheck   xdatly.Component[GateCheckInput, GateDecisionOutput] `component:"gate_check,path=/v1/authz/sdk/gates.check,method=POST,handler=NewGateCheck" mcp:"[{\"kind\":\"tool\",\"name\":\"authz.sdk.gates.check\"}]"`
	GateGet     xdatly.Component[GateInput, GateDocumentOutput]      `component:"gate_get,path=/v1/authz/sdk/gates.get,method=POST,handler=NewGateGet" mcp:"[{\"kind\":\"tool\",\"name\":\"authz.sdk.gates.get\"}]"`
	GateContext xdatly.Component[GateInput, GateContextOutput]       `component:"gate_context,path=/v1/authz/sdk/gates.context,method=POST,handler=NewGateContext" mcp:"[{\"kind\":\"tool\",\"name\":\"authz.sdk.gates.context\"}]"`
	GateReplace xdatly.Component[GateWriteInput, GateDocumentOutput] `component:"gate_replace,path=/v1/authz/sdk/gates.replace,method=POST,handler=NewGateReplace" mcp:"[{\"kind\":\"tool\",\"name\":\"authz.sdk.gates.replace\"}]"`
}

var Datly = new(Components)
var linkedTypes = []reflect.Type{reflect.TypeFor[Components](), reflect.TypeFor[CatalogInput](), reflect.TypeFor[CheckInput](), reflect.TypeFor[PolicyInput](), reflect.TypeFor[WriteInput](), reflect.TypeFor[GateCheckInput](), reflect.TypeFor[GateInput](), reflect.TypeFor[GateWriteInput]()}

func (Components) DatlyHandler(name string) func() (rhandler.TypedHandler, error) {
	switch name {
	case "NewCatalog":
		return custom.Factory(NewCatalog)
	case "NewCheck":
		return custom.Factory(NewCheck)
	case "NewGet":
		return custom.Factory(NewGet)
	case "NewPolicyContext":
		return custom.Factory(NewPolicyContext)
	case "NewCreate":
		return custom.Factory(NewCreate)
	case "NewReplace":
		return custom.Factory(NewReplace)
	case "NewGateCheck":
		return custom.Factory(NewGateCheck)
	case "NewGateGet":
		return custom.Factory(NewGateGet)
	case "NewGateContext":
		return custom.Factory(NewGateContext)
	case "NewGateReplace":
		return custom.Factory(NewGateReplace)
	}
	return nil
}

type subjectProvider struct {
	authz.Provider
	subject string
}

type subjectPrincipalResolver struct {
	gating.PrincipalResolver
	subject string
}

func (p subjectPrincipalResolver) ResolvePrincipal(ctx context.Context) (gating.Principal, error) {
	if p.PrincipalResolver == nil {
		return gating.Principal{}, authz.ErrDenied
	}
	principal, err := p.PrincipalResolver.ResolvePrincipal(ctx)
	if err != nil {
		if errors.Is(err, authz.ErrDenied) {
			return gating.Principal{}, authz.ErrDenied
		}
		return gating.Principal{}, gating.ErrUnavailable
	}
	if principal.Facts.Subject != p.subject {
		return gating.Principal{}, authz.ErrDenied
	}
	return principal, nil
}

func (p subjectProvider) Resolve(ctx context.Context) (authz.Facts, error) {
	if p.Provider == nil {
		return authz.Facts{}, authz.ErrDenied
	}
	facts, err := p.Provider.Resolve(ctx)
	if err != nil {
		if errors.Is(err, authz.ErrDenied) {
			return authz.Facts{}, authz.ErrDenied
		}
		return authz.Facts{}, authz.ErrUnavailable
	}
	if facts.Subject != p.subject {
		return authz.Facts{}, authz.ErrDenied
	}
	return facts, nil
}
func failure(code int, message string, cause error) error {
	return &xresponse.Error{Code: code, Payload: struct {
		Message string `json:"message"`
	}{message}, Cause: cause}
}
func publicError(err error) error {
	if errors.Is(err, authz.ErrConflict) {
		return failure(409, "policy revision conflict", err)
	}
	if errors.Is(err, authz.ErrIdentityDenied) {
		return failure(401, "authentication required", err)
	}
	if errors.Is(err, gating.ErrUnavailable) || errors.Is(err, authz.ErrUnavailable) {
		return failure(503, "authorization service unavailable", err)
	}
	return failure(403, "access denied", err)
}
func setup(ctx context.Context, session xhandler.Session, claims *jwt.Claims) (context.Context, Services, error) {
	if session == nil || session.Binder() == nil || claims == nil || claims.Subject == "" {
		return ctx, Services{}, failure(401, "authentication required", authz.ErrDenied)
	}
	value, found, err := session.Binder().Lookup(ctx, Capability)
	services, ok := value.(*Services)
	if err != nil || !found || !ok || services == nil {
		return ctx, Services{}, failure(503, "authorization service unavailable", err)
	}
	var header struct {
		Authorization string `bind:"kind=header,in=Authorization,required"`
	}
	if err = session.Binder().Bind(ctx, &header); err != nil || !strings.HasPrefix(header.Authorization, "Bearer ") || strings.TrimSpace(strings.TrimPrefix(header.Authorization, "Bearer ")) == "" {
		return ctx, Services{}, failure(401, "authentication required", err)
	}
	result := Services{}
	result.Catalog = services.Catalog
	if services.Authorization != nil {
		copied := *services.Authorization
		copied.Provider = subjectProvider{copied.Provider, claims.Subject}
		result.Authorization = &copied
	}
	if services.Policies != nil {
		copied := *services.Policies
		copied.Provider = subjectProvider{copied.Provider, claims.Subject}
		if copied.Management != nil {
			managed := *copied.Management
			managed.Provider = subjectProvider{managed.Provider, claims.Subject}
			copied.Management = &managed
		}
		result.Policies = &copied
	}
	if services.Gates != nil {
		copied := *services.Gates
		if copied.ACL != nil {
			acl := *copied.ACL
			acl.Provider = subjectProvider{acl.Provider, claims.Subject}
			copied.ACL = &acl
		}
		copied.Principals = subjectPrincipalResolver{copied.Principals, claims.Subject}
		result.Gates = &copied
	}
	if services.Requirements != nil {
		copied := *services.Requirements
		if copied.ACL != nil {
			acl := *copied.ACL
			acl.Provider = subjectProvider{acl.Provider, claims.Subject}
			copied.ACL = &acl
		}
		result.Requirements = &copied
	}
	return oauth.WithBearer(ctx, strings.TrimSpace(strings.TrimPrefix(header.Authorization, "Bearer "))), result, nil
}

type checkHandler struct{}

func NewCheck() xhandler.Contract[CheckInput, DecisionOutput] { return &checkHandler{} }
func (*checkHandler) Exec(ctx context.Context, session xhandler.Session, in *CheckInput, out *DecisionOutput) error {
	if in == nil || out == nil {
		return failure(400, "request required", nil)
	}
	ctx, services, err := setup(ctx, session, in.JWT)
	if err != nil {
		return err
	}
	if services.Authorization == nil {
		return failure(503, "authorization service unavailable", nil)
	}
	out.Decision, _, _, err = services.Authorization.AuthorizeWithStatus(ctx, authz.Request{Resource: in.Resource, Action: in.Action, Selection: in.Selection})
	if err != nil {
		return publicError(err)
	}
	return nil
}

type getHandler struct{}

func NewGet() xhandler.Contract[PolicyInput, PolicyOutput] { return &getHandler{} }
func (*getHandler) Exec(ctx context.Context, session xhandler.Session, in *PolicyInput, out *PolicyOutput) error {
	if in == nil || out == nil {
		return failure(400, "request required", nil)
	}
	ctx, services, err := setup(ctx, session, in.JWT)
	if err != nil {
		return err
	}
	if services.Authorization == nil {
		return failure(503, "policy service unavailable", nil)
	}
	out.Document, err = services.Authorization.GetWithStatus(ctx, in.Resource)
	if err != nil {
		return publicError(err)
	}
	return nil
}

type policyContextHandler struct{}

func NewPolicyContext() xhandler.Contract[PolicyInput, PolicyContextOutput] {
	return &policyContextHandler{}
}
func (*policyContextHandler) Exec(ctx context.Context, session xhandler.Session, in *PolicyInput, out *PolicyContextOutput) error {
	if in == nil || out == nil {
		return failure(400, "request required", nil)
	}
	ctx, services, err := setup(ctx, session, in.JWT)
	if err != nil {
		return err
	}
	if services.Authorization == nil {
		return failure(503, "authorization service unavailable", nil)
	}
	out.Context, err = services.Authorization.EditorContextWithStatus(ctx, in.Resource)
	if err != nil {
		return publicError(err)
	}
	if services.Policies == nil {
		out.Context.CanManage = false
		return nil
	}
	out.Context.CanManage, err = services.Policies.CanReplace(ctx, in.Resource)
	if err != nil {
		return publicError(err)
	}
	return nil
}

type writeHandler struct{ create bool }

func NewCreate() xhandler.Contract[WriteInput, PolicyOutput]  { return &writeHandler{create: true} }
func NewReplace() xhandler.Contract[WriteInput, PolicyOutput] { return &writeHandler{} }
func (h *writeHandler) Exec(ctx context.Context, session xhandler.Session, in *WriteInput, out *PolicyOutput) error {
	if in == nil || out == nil {
		return failure(400, "request required", nil)
	}
	ctx, services, err := setup(ctx, session, in.JWT)
	if err != nil {
		return err
	}
	if services.Policies == nil {
		return failure(503, "policy service unavailable", nil)
	}
	if h.create {
		out.Document, err = services.Policies.Create(ctx, in.Document)
	} else {
		out.Document, err = services.Policies.Replace(ctx, in.Document)
	}
	if err != nil {
		return publicError(err)
	}
	return nil
}

type gateCheckHandler struct{}

func NewGateCheck() xhandler.Contract[GateCheckInput, GateDecisionOutput] { return &gateCheckHandler{} }
func (*gateCheckHandler) Exec(ctx context.Context, session xhandler.Session, in *GateCheckInput, out *GateDecisionOutput) error {
	if in == nil || out == nil {
		return failure(400, "request required", nil)
	}
	ctx, services, err := setup(ctx, session, in.JWT)
	if err != nil {
		return err
	}
	if services.Gates == nil {
		return failure(503, "gate service unavailable", nil)
	}
	var nonce [16]byte
	if _, err = rand.Read(nonce[:]); err != nil {
		return failure(503, "gate service unavailable", err)
	}
	out.Decision, err = services.Gates.Evaluate(ctx, gating.Request{RequestID: hex.EncodeToString(nonce[:]), Resource: in.Resource, Action: in.Action, Selected: in.Selected})
	if err != nil {
		return publicError(err)
	}
	return nil
}

type gateGetHandler struct{}

func NewGateGet() xhandler.Contract[GateInput, GateDocumentOutput] { return &gateGetHandler{} }
func (*gateGetHandler) Exec(ctx context.Context, session xhandler.Session, in *GateInput, out *GateDocumentOutput) error {
	if in == nil || out == nil {
		return failure(400, "request required", nil)
	}
	ctx, services, err := setup(ctx, session, in.JWT)
	if err != nil {
		return err
	}
	if services.Requirements == nil {
		return failure(503, "gate administration unavailable", nil)
	}
	out.Document, err = services.Requirements.Get(ctx, in.Resource, in.Action)
	if err != nil {
		return publicError(err)
	}
	return nil
}

type gateContextHandler struct{}

func NewGateContext() xhandler.Contract[GateInput, GateContextOutput] { return &gateContextHandler{} }
func (*gateContextHandler) Exec(ctx context.Context, session xhandler.Session, in *GateInput, out *GateContextOutput) error {
	if in == nil || out == nil {
		return failure(400, "request required", nil)
	}
	ctx, services, err := setup(ctx, session, in.JWT)
	if err != nil {
		return err
	}
	if services.Requirements == nil {
		return failure(503, "gate administration unavailable", nil)
	}
	out.Context, err = services.Requirements.Context(ctx, in.Resource, in.Action)
	if err != nil {
		return publicError(err)
	}
	return nil
}

type gateReplaceHandler struct{}

func NewGateReplace() xhandler.Contract[GateWriteInput, GateDocumentOutput] {
	return &gateReplaceHandler{}
}
func (*gateReplaceHandler) Exec(ctx context.Context, session xhandler.Session, in *GateWriteInput, out *GateDocumentOutput) error {
	if in == nil || out == nil {
		return failure(400, "request required", nil)
	}
	ctx, services, err := setup(ctx, session, in.JWT)
	if err != nil {
		return err
	}
	if services.Requirements == nil {
		return failure(503, "gate administration unavailable", nil)
	}
	out.Document, err = services.Requirements.Replace(ctx, in.Resource, in.Action, in.ExpectedRevision, in.Requirements)
	if err != nil {
		return publicError(err)
	}
	return nil
}
