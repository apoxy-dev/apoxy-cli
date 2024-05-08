package apiserver

import (
	"context"
	"time"

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
)

// NewKineStorage creates a new kine storage.
func NewKineStorage(ctx context.Context, dsn string) rest.StoreFn {
	return func(scheme *runtime.Scheme, s *genericregistry.Store, options *generic.StoreOptions) {
		options.RESTOptions = &kineRESTOptionsGetter{
			ctx:            ctx,
			scheme:         scheme,
			dsn:            dsn,
			groupVersioner: s.StorageVersioner,
		}
	}
}

type kineRESTOptionsGetter struct {
	ctx            context.Context
	scheme         *runtime.Scheme
	dsn            string
	groupVersioner runtime.GroupVersioner
}

func (g *kineRESTOptionsGetter) GetRESTOptions(resource schema.GroupResource) (generic.RESTOptions, error) {
	etcdConfig, err := endpoint.Listen(g.ctx, endpoint.Config{
		Endpoint: g.dsn,
	})
	if err != nil {
		return generic.RESTOptions{}, err
	}
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
					ServerList:    etcdConfig.Endpoints,
					TrustedCAFile: etcdConfig.TLSConfig.CAFile,
					CertFile:      etcdConfig.TLSConfig.CertFile,
					KeyFile:       etcdConfig.TLSConfig.KeyFile,
				},
			},
		},
	}, nil
}
