package api

import (
	"context"
	"github.com/viant/authz"
	"github.com/viant/scy/auth/jwt"
	xhandler "github.com/viant/xdatly/handler"
)

type NamedInput struct {
	JWT              *jwt.Claims           `parameter:"JWT,kind=header,in=Authorization,dataType=string" codec:"JwtClaim" json:"-"`
	Operation        string                `parameter:"Operation,kind=body,in=operation,required=true" json:"operation"`
	ID               string                `parameter:"ID,kind=body,in=id" json:"id,omitempty"`
	Reference        authz.NamedReference  `parameter:"Reference,kind=body,in=reference" json:"reference,omitempty"`
	Definition       authz.NamedDefinition `parameter:"Definition,kind=body,in=definition" json:"definition,omitempty"`
	Resource         authz.Resource        `parameter:"Resource,kind=body,in=resource" json:"resource,omitempty"`
	ExpectedRevision int64                 `parameter:"ExpectedRevision,kind=body,in=expectedRevision" json:"expectedRevision,omitempty"`
	Actions          []string              `parameter:"Actions,kind=body,in=actions" json:"actions,omitempty"`
}
type NamedOutput struct {
	Policies []authz.NamedPolicy `json:"policies,omitempty"`
	Policy   *authz.NamedPolicy  `json:"policy,omitempty"`
	Impacts  []authz.NamedImpact `json:"impacts,omitempty"`
	Document *authz.Document     `json:"document,omitempty"`
}
type namedHandler struct{}

func NewNamed() xhandler.Contract[NamedInput, NamedOutput] { return &namedHandler{} }
func (*namedHandler) Exec(ctx context.Context, session xhandler.Session, in *NamedInput, out *NamedOutput) error {
	if in == nil || out == nil {
		return failure(400, "request required", nil)
	}
	ctx, services, err := setup(ctx, session, in.JWT)
	if err != nil {
		return err
	}
	manager := services.Named
	if manager == nil && services.Policies != nil {
		if inventory, ok := services.Policies.Store.(authz.PolicyInventory); ok {
			manager = &authz.NamedAdministration{Policies: services.Policies, Inventory: inventory}
		}
	}
	if manager == nil {
		return failure(503, "named policy management unavailable", nil)
	}
	switch in.Operation {
	case "list":
		out.Policies, err = manager.List(ctx)
	case "create":
		var value authz.NamedPolicy
		value, err = manager.Create(ctx, in.ID, in.Definition)
		if err == nil {
			out.Policy = &value
		}
	case "update":
		var value authz.NamedPolicy
		value, out.Impacts, err = manager.Update(ctx, in.Reference, in.Definition)
		if err == nil {
			out.Policy = &value
		}
	case "impact":
		out.Impacts, err = manager.Impact(ctx, in.Reference.Resource)
	case "assign":
		var value authz.Document
		value, err = manager.Assign(ctx, in.Resource, in.ExpectedRevision, in.Actions, in.Reference)
		if err == nil {
			out.Document = &value
		}
	case "archive":
		var value authz.Document
		value, err = manager.Archive(ctx, in.Reference)
		if err == nil {
			out.Document = &value
		}
	default:
		return failure(400, "unknown named policy operation", nil)
	}
	if err != nil {
		return publicError(err)
	}
	return nil
}
