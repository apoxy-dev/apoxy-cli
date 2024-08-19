package translator

import (
	"errors"
	"fmt"
	"strings"

	"github.com/apoxy-dev/apoxy-cli/internal/gateway/xds/types"
	clusterv3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	routev3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	dfpclusterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	dfpconfigv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/dynamic_forward_proxy/v3"
	dfpfilterv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/dynamic_forward_proxy/v3"
	hcmv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	resourcev3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/apoxy-dev/apoxy-cli/internal/gateway/ir"
)

const (
	dynamicForwardProxyFilter = "envoy.filters.http.dynamic_forward_proxy"
)

func init() {
	registerHTTPFilter(&dynamicForwardProxy{})
}

type dynamicForwardProxy struct{}

var _ httpFilter = &dynamicForwardProxy{}

// patchHCM
func (*dynamicForwardProxy) patchHCM(mgr *hcmv3.HttpConnectionManager, irListener *ir.HTTPListener) error {
	if mgr == nil {
		return errors.New("hcm is nil")
	}
	if irListener == nil {
		return errors.New("ir listener is nil")
	}

	var errs error
	for _, r := range irListener.Routes {
		if hcmContainsFilter(mgr, dynamicForwardProxyFilterName(r)) {
			continue
		}
		if !routeContainsDynamicForwardProxy(r) {
			continue
		}

		filter, err := buildHCMDynamicForwardProxyFilter(r, r.Destination.Settings[0].DynamicForwardProxy)
		if err != nil {
			errs = errors.Join(errs, err)
			continue
		}

		mgr.HttpFilters = append(mgr.HttpFilters, filter)
	}

	return errs
}

func dynamicForwardProxyFilterName(r *ir.HTTPRoute) string {
	return perRouteFilterName(dynamicForwardProxyFilter, r.Name)
}

func buildHCMDynamicForwardProxyFilter(r *ir.HTTPRoute, dfp *ir.DynamicForwardProxy) (*hcmv3.HttpFilter, error) {
	if r == nil {
		return nil, errors.New("ir route is nil")
	}

	filterConfig := &dfpfilterv3.FilterConfig{
		ImplementationSpecifier: &dfpfilterv3.FilterConfig_DnsCacheConfig{
			DnsCacheConfig: dnsCacheConfig(dfp),
		},
	}
	pb, err := anypb.New(filterConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal dynamic forward proxy filter config: %w", err)
	}

	return &hcmv3.HttpFilter{
		Name: dynamicForwardProxyFilterName(r),
		ConfigType: &hcmv3.HttpFilter_TypedConfig{
			TypedConfig: pb,
		},
		Disabled: true,
	}, nil
}

func dnsCacheConfig(dfp *ir.DynamicForwardProxy) *dfpconfigv3.DnsCacheConfig {
	if dfp == nil {
		return nil
	}

	dnsLookupFamily := clusterv3.Cluster_AUTO
	if dfp.DNSLookupFamily != "" {
		dnsLookupFamily = clusterv3.Cluster_DnsLookupFamily(
			clusterv3.Cluster_DnsLookupFamily_value[strings.ToUpper(string(dfp.DNSLookupFamily))])
	}
	var dnsRefreshRate *durationpb.Duration
	if dfp.DNSRefreshRate != nil {
		dnsRefreshRate = durationpb.New(dfp.DNSRefreshRate.Duration)
	}
	var hostTTL *durationpb.Duration
	if dfp.HostTTL != nil {
		hostTTL = durationpb.New(dfp.HostTTL.Duration)
	}
	var maxHosts *wrapperspb.UInt32Value
	if dfp.MaxHosts != nil {
		maxHosts = wrapperspb.UInt32(*dfp.MaxHosts)
	}

	return &dfpconfigv3.DnsCacheConfig{
		Name:            dfp.Name,
		DnsLookupFamily: dnsLookupFamily,
		DnsRefreshRate:  dnsRefreshRate,
		HostTtl:         hostTTL,
		MaxHosts:        maxHosts,
	}
}

func (*dynamicForwardProxy) patchResources(
	tCtx *types.ResourceVersionTable,
	routes []*ir.HTTPRoute,
) error {
	if tCtx == nil || tCtx.XdsResources == nil {
		return errors.New("xds resource table is nil")
	}

	var errs error
	for _, r := range routes {
		if !routeContainsDynamicForwardProxy(r) {
			continue
		}

		if err := createDynamicForwardProxyCluster(
			r.Destination.Settings[0].DynamicForwardProxy,
			tCtx,
		); err != nil && !errors.Is(err, ErrXdsClusterExists) {
			errs = errors.Join(errs, err)
		}
	}

	return errs
}

func createDynamicForwardProxyCluster(
	dfp *ir.DynamicForwardProxy,
	tCtx *types.ResourceVersionTable,
) error {
	if dfp == nil {
		return errors.New("dynamic forward proxy is nil")
	}

	if findXdsCluster(tCtx, dfp.Name) != nil {
		return ErrXdsClusterExists
	}

	pb, err := anypb.New(&dfpclusterv3.ClusterConfig{
		ClusterImplementationSpecifier: &dfpclusterv3.ClusterConfig_DnsCacheConfig{
			DnsCacheConfig: dnsCacheConfig(dfp),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to marshal dynamic forward proxy cluster config: %w", err)
	}

	cluster := &clusterv3.Cluster{
		Name:     dfp.Name,
		LbPolicy: clusterv3.Cluster_CLUSTER_PROVIDED,
		ClusterDiscoveryType: &clusterv3.Cluster_ClusterType{
			ClusterType: &clusterv3.Cluster_CustomClusterType{
				Name:        "envoy.clusters.dynamic_forward_proxy",
				TypedConfig: pb,
			},
		},
	}

	return tCtx.AddXdsResource(resourcev3.ClusterType, cluster)
}

func (*dynamicForwardProxy) patchRoute(route *routev3.Route, irRoute *ir.HTTPRoute) error {
	if route == nil {
		return errors.New("xds route is nil")
	}
	if irRoute == nil {
		return errors.New("ir route is nil")
	}
	if irRoute.ExtensionRefs == nil {
		return nil
	}

	if routeContainsDynamicForwardProxy(irRoute) {
		route.Action = &routev3.Route_Route{
			Route: &routev3.RouteAction{
				ClusterSpecifier: &routev3.RouteAction_Cluster{
					Cluster: irRoute.Destination.Settings[0].DynamicForwardProxy.Name,
				},
			},
		}
	}

	return enableFilterOnRoute(route, dynamicForwardProxyFilterName(irRoute))
}

func routeContainsDynamicForwardProxy(r *ir.HTTPRoute) bool {
	if r == nil {
		return false
	}

	if len(r.Destination.Settings) != 1 || r.Destination.Settings[0].DynamicForwardProxy == nil {
		return false
	}

	return true
}
