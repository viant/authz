package api

import (
	"context"
	"fmt"
	"github.com/viant/datly/bootstrap"
	"github.com/viant/datly/runtime/handler/provider"
	"github.com/viant/datly/runtime/registry"
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
		result = append(result, &registry.RegisteredComponent{Component: artifact.Component, Input: artifact.Input, Output: artifact.Output, OutputType: source.LinkedOutputType, Handler: handler, Providers: nil})
		result[len(result)-1].Providers = append(result[len(result)-1].Providers, provider.Static(Capability, services))
	}
	return result, nil
}
