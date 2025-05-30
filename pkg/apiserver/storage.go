package apiserver

import (
	"context"
	"os"
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
)

// NewKineStorage creates a new kine storage.
func NewKineStorage(ctx context.Context, dsn string) (rest.StoreFn, error) {
	tmpDir := os.Getenv("KINE_TMPDIR")
	if tmpDir == "" {
		tmpDir = os.TempDir()
	}
	etcdConfig, err := endpoint.Listen(ctx, endpoint.Config{
		Endpoint: dsn,
		Listener: "unix://" + tmpDir + "/apiserver-kine.sock",
		ConnectionPoolConfig: driversgeneric.ConnectionPoolConfig{
			MaxOpen: goruntime.NumCPU(),
		},
		// Default is taken from kine: https://github.com/k3s-io/kine/blob/c1b2bd81f697c6b7aec85ea2562bcbcdfb981307/pkg/app/app.go#L106
		NotifyInterval: 5 * time.Second,
		// Default is taken from kine: https://github.com/k3s-io/kine/blob/c1b2bd81f697c6b7aec85ea2562bcbcdfb981307/pkg/app/app.go#L112
		EmulatedETCDVersion: "3.5.13",
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

// GetRESTOptions implements generic.RESTOptionsGetter.
func (g *kineRESTOptionsGetter) GetRESTOptions(resource schema.GroupResource, _ runtime.Object) (generic.RESTOptions, error) {
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
