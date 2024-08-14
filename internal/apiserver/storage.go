package apiserver

import (
	"context"
	goruntime "runtime"
	"time"

	driversgeneric "github.com/k3s-io/kine/pkg/drivers/generic"
	"github.com/k3s-io/kine/pkg/endpoint"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/runtime/serializer/json"
	"k8s.io/apiserver/pkg/registry/generic"
	genericregistry "k8s.io/apiserver/pkg/registry/generic/registry"
	"k8s.io/apiserver/pkg/storage/storagebackend"
	"k8s.io/apiserver/pkg/util/flowcontrol/request"
	"sigs.k8s.io/apiserver-runtime/pkg/builder/rest"

	"github.com/apoxy-dev/apoxy-cli/config"
)

// NewKineStorage creates a new kine storage.
func NewKineStorage(ctx context.Context, dsn string) (rest.StoreFn, error) {
	etcdConfig, err := endpoint.Listen(ctx, endpoint.Config{
		Endpoint: dsn,
		Listener: "unix://" + config.ApoxyDir() + "/kine.sock",
		ConnectionPoolConfig: driversgeneric.ConnectionPoolConfig{
			MaxOpen: goruntime.NumCPU(),
		},
	})
	if err != nil {
		return nil, err
	}
	return func(scheme *runtime.Scheme, s *genericregistry.Store, options *generic.StoreOptions) {
		options.RESTOptions = &kineRESTOptionsGetter{
			scheme:         scheme,
			etcdConfig:     etcdConfig,
			groupVersioner: s.StorageVersioner,
		}
	}, nil
}

type kineRESTOptionsGetter struct {
	scheme         *runtime.Scheme
	etcdConfig     endpoint.ETCDConfig
	groupVersioner runtime.GroupVersioner
}

func (g *kineRESTOptionsGetter) GetRESTOptions(resource schema.GroupResource) (generic.RESTOptions, error) {
	s := json.NewSerializer(json.DefaultMetaFactory, g.scheme, g.scheme, false)
	codec := serializer.NewCodecFactory(g.scheme).
		CodecForVersions(s, s, g.groupVersioner, g.groupVersioner)
	return generic.RESTOptions{
		ResourcePrefix:            resource.String(),
		Decorator:                 genericregistry.StorageWithCacher(),
		EnableGarbageCollection:   true,
		DeleteCollectionWorkers:   1,
		CountMetricPollPeriod:     time.Minute,
		StorageObjectCountTracker: request.NewStorageObjectCountTracker(),
		StorageConfig: &storagebackend.ConfigForResource{
			GroupResource: resource,
			Config: storagebackend.Config{
				Prefix: "/kine/",
				Codec:  codec,
				Transport: storagebackend.TransportConfig{
					ServerList:    g.etcdConfig.Endpoints,
					TrustedCAFile: g.etcdConfig.TLSConfig.CAFile,
					CertFile:      g.etcdConfig.TLSConfig.CertFile,
					KeyFile:       g.etcdConfig.TLSConfig.KeyFile,
				},
			},
		},
	}, nil
}
