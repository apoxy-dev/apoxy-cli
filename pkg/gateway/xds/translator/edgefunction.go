package translator

import (
	"errors"
	"fmt"

	"github.com/apoxy-dev/apoxy-cli/pkg/gateway/xds/types"
	golangv3alpha "github.com/envoyproxy/go-control-plane/contrib/envoy/extensions/filters/http/golang/v3alpha"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/structpb"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"

	extensionsv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/extensions/v1alpha1"
	"github.com/apoxy-dev/apoxy-cli/pkg/gateway/ir"
)

const (
	golangPluginFilter = "envoy.filters.http.golang"
)

var (
	conv = runtime.DefaultUnstructuredConverter
)

func init() {
	registerHTTPFilter(&edgeFunc{})
}

type edgeFunc struct{}

var _ httpFilter = &edgeFunc{}

// patchHCM builds and appends the EdgeFunction extension filter to the HttpConnectionManager
// if applicable, and it does not already exist.
func (*edgeFunc) patchHCM(mgr *hcmv3.HttpConnectionManager, irListener *ir.HTTPListener) error {
	if mgr == nil {
		return errors.New("hcm is nil")
	}
	if irListener == nil {
		return errors.New("ir listener is nil")
	}

	var errs error
	for _, route := range irListener.Routes {
		for _, er := range route.ExtensionRefs {
			if er.Object.GroupVersionKind().Group != extensionsv1alpha1.GroupVersion.Group ||
				er.Object.GroupVersionKind().Kind != "EdgeFunction" {
				continue
			}

			if hcmContainsFilter(mgr, edgeFuncFilterName(er.Object)) {
				continue
			}

			filter, err := buildHCMEdgeFuncFilter(er.Object)
			if err != nil {
				errs = errors.Join(errs, err)
				continue
			}

			mgr.HttpFilters = append(mgr.HttpFilters, filter)
		}
	}

	return errs
}

// buildHCMEdgeFuncFilter returns an HCM HttpFilter for the associated EdgeFunction.
func buildHCMEdgeFuncFilter(un *unstructured.Unstructured) (*hcmv3.HttpFilter, error) {
	var fun extensionsv1alpha1.EdgeFunction
	if err := conv.FromUnstructured(un.UnstructuredContent(), &fun); err != nil {
		return nil, err
	}

	if fun.Spec.Code.GoPluginSource == nil {
		return nil, errors.New("edge function source is not a Go plugin")
	}

	pluginConfig := structpb.Struct{}
	// Parse JSON string into Struct
	if fun.Spec.Code.GoPluginSource.PluginConfig != "" {
		// yaml to json
		var jsonBytes []byte
		jsonBytes, err := yaml.YAMLToJSON([]byte(fun.Spec.Code.GoPluginSource.PluginConfig))
		if err != nil {
			return nil, fmt.Errorf("failed to convert yaml to json: %w", err)
		}

		// json to struct
		if err := protojson.Unmarshal(jsonBytes, &pluginConfig); err != nil {
			return nil, fmt.Errorf("failed to unmarshal plugin config: %w", err)
		}
	}
	pluginAny, err := anypb.New(&pluginConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal plugin config: %w", err)
	}

	pluginName := fun.Name
	if fun.Spec.Code.Name != "" {
		pluginName = fun.Spec.Code.Name
	}
	var edgeFuncAny *anypb.Any
	if fun.Spec.Code.GoPluginSource != nil {
		msg := &golangv3alpha.Config{
			LibraryId:    fun.Status.Live,
			LibraryPath:  fmt.Sprintf("go/%s/func.so", fun.Status.Live),
			PluginName:   pluginName,
			PluginConfig: pluginAny,
			//MergePolicy: ...
		}
		edgeFuncAny, err = anypb.New(msg)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Go plugin config: %w", err)
		}
	} else {
		return nil, errors.New("edge function source is not a Go plugin")
	}

	return &hcmv3.HttpFilter{
		Name:     edgeFuncFilterName(un),
		Disabled: true, // Filters are enabled on a per-route basis.
		ConfigType: &hcmv3.HttpFilter_TypedConfig{
			TypedConfig: edgeFuncAny,
		},
	}, nil
}

func edgeFuncFilterName(un *unstructured.Unstructured) string {
	return perRouteFilterName(golangPluginFilter, un.GetName())
}

func (*edgeFunc) patchResources(
	tCtx *types.ResourceVersionTable,
	routes []*ir.HTTPRoute,
) error {
	return nil
}

func (*edgeFunc) patchRoute(route *routev3.Route, irRoute *ir.HTTPRoute) error {
	if route == nil {
		return errors.New("xds route is nil")
	}
	if irRoute == nil {
		return errors.New("ir route is nil")
	}
	if irRoute.ExtensionRefs == nil {
		return nil
	}

	for _, er := range irRoute.ExtensionRefs {
		if er.Object.GroupVersionKind().Group != extensionsv1alpha1.GroupVersion.Group ||
			er.Object.GroupVersionKind().Kind != "EdgeFunction" {
			continue
		}

		if err := enableFilterOnRoute(route, edgeFuncFilterName(er.Object)); err != nil {
			return err
		}
	}
	return nil
}
