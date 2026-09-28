// Package api declares Datly 1.0 components that are the authz SDK endpoints.
package api

import (
	"context"
	"errors"
	"github.com/viant/authz"
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
const Package = "github.com/viant/authz/datly/api"

type Services struct {
	Authorization *authz.Service
	Policies      *authz.Administration
}
type CheckInput struct {
	JWT       *jwt.Claims     `parameter:"JWT,kind=header,in=Authorization,dataType=string,required=true,errorCode=401" codec:"JwtClaim" json:"-"`
	Resource  authz.Resource  `parameter:"Resource,kind=body,in=resource,required=true" json:"resource"`
	Action    string          `parameter:"Action,kind=body,in=action,required=true" json:"action"`
	Selection *[]authz.Entity `parameter:"Selection,kind=body,in=selection" json:"selection,omitempty"`
}
type PolicyInput struct {
	JWT      *jwt.Claims    `parameter:"JWT,kind=header,in=Authorization,dataType=string,required=true,errorCode=401" codec:"JwtClaim" json:"-"`
	Resource authz.Resource `parameter:"Resource,kind=body,in=resource,required=true" json:"resource"`
}
type WriteInput struct {
	JWT      *jwt.Claims    `parameter:"JWT,kind=header,in=Authorization,dataType=string,required=true,errorCode=401" codec:"JwtClaim" json:"-"`
	Document authz.Document `parameter:"Document,kind=body,in=document,required=true" json:"document"`
}
type DecisionOutput struct {
	Decision authz.Decision `json:"decision"`
}
type PolicyOutput struct {
	Document authz.Document `json:"document"`
}
type Components struct {
	Check   xdatly.Component[CheckInput, DecisionOutput] `component:"check,path=/v1/authz/sdk/authorization.check,method=POST,handler=NewCheck" mcp:"[{\"kind\":\"tool\",\"name\":\"authz.sdk.authorization.check\"}]"`
	Get     xdatly.Component[PolicyInput, PolicyOutput]  `component:"policy_get,path=/v1/authz/sdk/policies.get,method=POST,handler=NewGet" mcp:"[{\"kind\":\"tool\",\"name\":\"authz.sdk.policies.get\"}]"`
	Create  xdatly.Component[WriteInput, PolicyOutput]   `component:"policy_create,path=/v1/authz/sdk/policies.create,method=POST,handler=NewCreate" mcp:"[{\"kind\":\"tool\",\"name\":\"authz.sdk.policies.create\"}]"`
	Replace xdatly.Component[WriteInput, PolicyOutput]   `component:"policy_replace,path=/v1/authz/sdk/policies.replace,method=POST,handler=NewReplace" mcp:"[{\"kind\":\"tool\",\"name\":\"authz.sdk.policies.replace\"}]"`
}

var Datly = new(Components)
var linkedTypes = []reflect.Type{reflect.TypeFor[Components](), reflect.TypeFor[CheckInput](), reflect.TypeFor[PolicyInput](), reflect.TypeFor[WriteInput]()}

func (Components) DatlyHandler(name string) func() (rhandler.TypedHandler, error) {
	switch name {
	case "NewCheck":
		return custom.Factory(NewCheck)
	case "NewGet":
		return custom.Factory(NewGet)
	case "NewCreate":
		return custom.Factory(NewCreate)
	case "NewReplace":
		return custom.Factory(NewReplace)
	}
	return nil
}

type subjectProvider struct {
	authz.Provider
	subject string
}

func (p subjectProvider) Resolve(ctx context.Context) (authz.Facts, error) {
	if p.Provider == nil {
		return authz.Facts{}, authz.ErrDenied
	}
	facts, err := p.Provider.Resolve(ctx)
	if err != nil || facts.Subject != p.subject {
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
	if services.Authorization != nil {
		copied := *services.Authorization
		copied.Provider = subjectProvider{copied.Provider, claims.Subject}
		result.Authorization = &copied
	}
	if services.Policies != nil {
		copied := *services.Policies
		copied.Provider = subjectProvider{copied.Provider, claims.Subject}
		result.Policies = &copied
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
	out.Decision, err = services.Authorization.Authorize(ctx, authz.Request{Resource: in.Resource, Action: in.Action, Selection: in.Selection})
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
	if services.Policies == nil {
		return failure(503, "policy service unavailable", nil)
	}
	out.Document, err = services.Policies.Get(ctx, in.Resource)
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
