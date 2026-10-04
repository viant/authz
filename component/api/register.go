package api

import (
	"context"
	"fmt"
	"reflect"

	"github.com/viant/bindly/locator"
	"github.com/viant/datly/bootstrap"
	"github.com/viant/datly/runtime/handler/provider"
	"github.com/viant/datly/runtime/registry"
	dtag "github.com/viant/datly/tag"
	xcodec "github.com/viant/xdatly/codec"
)

// Registrations discovers the declared SDK components using native Datly
// bootstrap. The host supplies its verifier and narrow authz capabilities.
// Other projects can use these same components in their own runtime.
func Registrations(ctx context.Context, baseDir string, services *Services, codecs xcodec.Factory) ([]*registry.RegisteredComponent, error) {
	if services == nil || codecs == nil {
		return nil, fmt.Errorf("authz services and JWT codec factory required")
	}
	routes, err := (bootstrap.PackageDiscovery{BaseDir: baseDir, Include: []string{Package}, Holders: []any{Datly}, RequireLinked: true}).Discover(ctx)
	if err != nil {
		return nil, err
	}
	result := make([]*registry.RegisteredComponent, 0, len(routes))
	for _, source := range routes {
		registered, err := registration(source, services, codecs)
		if err != nil {
			return nil, err
		}
		result = append(result, registered)
	}
	return result, nil
}

// LinkedRegistrations builds the same SDK routes from the linked component
// holder. Embedding binaries can mount authz without shipping this module's Go
// source tree. The holder's typed fields and tags remain the route authority.
func LinkedRegistrations(services *Services, codecs xcodec.Factory) ([]*registry.RegisteredComponent, error) {
	if services == nil || codecs == nil {
		return nil, fmt.Errorf("authz services and JWT codec factory required")
	}
	holder := reflect.TypeFor[Components]()
	result := make([]*registry.RegisteredComponent, 0, holder.NumField())
	for index := 0; index < holder.NumField(); index++ {
		field := holder.Field(index)
		tag, present, err := dtag.ParseComponent(field.Tag)
		if err != nil {
			return nil, err
		}
		if !present {
			continue
		}
		input, hasInput := field.Type.FieldByName("Input")
		output, hasOutput := field.Type.FieldByName("Output")
		if !hasInput || !hasOutput {
			return nil, fmt.Errorf("component %s has no linked input/output contract", field.Name)
		}
		source := &bootstrap.RouteSource{HolderType: holder.Name(), FieldName: field.Name,
			PackageName: "api", PackagePath: Package, Tag: tag,
			InputType: input.Type.Name(), OutputType: output.Type.Name(),
			LinkedInputType: input.Type, LinkedOutputType: output.Type,
			LinkedHandler: Datly.DatlyHandler(tag.Handler)}
		registered, err := registration(source, services, codecs)
		if err != nil {
			return nil, err
		}
		result = append(result, registered)
	}
	if len(result) == 0 {
		return nil, fmt.Errorf("authz SDK has no linked components")
	}
	return result, nil
}

func registration(source *bootstrap.RouteSource, services *Services, codecs xcodec.Factory) (*registry.RegisteredComponent, error) {
	component, err := source.Resolve(source.LinkedInputType, source.LinkedOutputType)
	if err != nil {
		return nil, err
	}
	if source.LinkedHandler == nil {
		return nil, fmt.Errorf("handler missing for %s", source.FieldName)
	}
	handler, err := source.LinkedHandler()
	if err != nil {
		return nil, err
	}
	artifact, err := bootstrap.BuildArtifact(bootstrap.ArtifactInput{Component: component, InputType: source.LinkedInputType, OutputType: source.LinkedOutputType, Handler: handler, CodecFactory: codecs, HandlerOwnedOutput: true})
	if err != nil {
		return nil, err
	}
	return &registry.RegisteredComponent{Component: artifact.Component, Input: artifact.Input, Output: artifact.Output, OutputType: source.LinkedOutputType, Handler: handler, Providers: []locator.Provider{provider.Static(Capability, services)}}, nil
}
