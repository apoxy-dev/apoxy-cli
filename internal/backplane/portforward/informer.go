// Package portforward watches a port on a ProxyReplica and forwards from
// a local port to the remote port on the ProxyReplica.
package portforward

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/workqueue"

	"github.com/apoxy-dev/apoxy-cli/client/informers"
	"github.com/apoxy-dev/apoxy-cli/client/versioned"
	"github.com/apoxy-dev/apoxy-cli/internal/backplane/drivers"
	"github.com/apoxy-dev/apoxy-cli/internal/log"

	ctrlv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/controllers/v1alpha1"
)

const (
	resyncPeriod = 1 * time.Minute
)

// PortForwarder forwards a local port to a remote port.
type PortForwarder struct {
	proxyName   string
	replicaName string
	cname       string

	factory  informers.SharedInformerFactory
	informer cache.SharedIndexInformer
	wq       workqueue.RateLimitingInterface
	// portStopCh is a map of ports to the corresponding subroutines' stop channels.
	portStopCh map[string]chan struct{}
}

// NewPortForwarder creates a new PortForwarder.
// proxyName specifies a Proxy to watch and cname is the container to forward to.
// The local port is the same as the remote port if available.
func NewPortForwarder(rc *rest.Config, proxyName, replicaName, cname string) (*PortForwarder, error) {
	c, err := versioned.NewForConfig(rc)
	if err != nil {
		return nil, fmt.Errorf("could not create client: %v", err)
	}
	return &PortForwarder{
		proxyName:   proxyName,
		replicaName: replicaName,
		cname:       cname,
		factory: informers.NewSharedInformerFactoryWithOptions(
			c,
			resyncPeriod,
			informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
				opts.FieldSelector = "metadata.name=" + proxyName
			}),
		),
		wq:         workqueue.NewNamedRateLimitingQueue(workqueue.DefaultControllerRateLimiter(), "portforward"),
		portStopCh: make(map[string]chan struct{}),
	}, nil
}

func findReplicaStatus(p *ctrlv1alpha1.Proxy, rname string) (*ctrlv1alpha1.ProxyReplicaStatus, bool) {
	for i := range p.Status.Replicas {
		if p.Status.Replicas[i].Name == rname {
			return p.Status.Replicas[i], true
		}
	}
	return nil, false
}

func (pf *PortForwarder) sync(key string) error {
	obj, exists, err := pf.informer.GetIndexer().GetByKey(key)
	if err != nil {
		return fmt.Errorf("could not get object by key %q: %v", key, err)
	}

	proxy := obj.(*ctrlv1alpha1.Proxy)
	if !exists {
		for p, stopCh := range pf.portStopCh {
			delete(pf.portStopCh, p)
			close(stopCh)
			fmt.Printf("Stopped listening on :%s\n", p)
		}
		return nil
	}

	rs, ok := findReplicaStatus(proxy, pf.replicaName)
	if !ok {
		log.Infof("replica %q not found in proxy %q", pf.replicaName, pf.proxyName)
		return nil
	}

	for _, p := range rs.Ports {
		if _, ok := pf.portStopCh[p]; !ok {
			ss := strings.Split(p, "/")
			if len(ss) != 2 {
				return fmt.Errorf("invalid port %q", p)
			}
			port, proto := ss[0], ss[1]
			portn, err := strconv.Atoi(port)
			if err != nil {
				return fmt.Errorf("invalid port %q: %v", p, err)
			}

			stopCh := make(chan struct{})
			switch proto {
			case "tcp":
				fmt.Printf("Listening on %s\n", port)
				go drivers.ForwardTCP(stopCh, pf.cname, portn, portn)
			default:
				return fmt.Errorf("invalid protocol %q", proto)
			}

			pf.portStopCh[p] = stopCh
		}
	}
	for p, stopCh := range pf.portStopCh {
		if !slices.Contains(rs.Ports, p) {
			delete(pf.portStopCh, p)
			close(stopCh)
			fmt.Printf("Stopped listening on :%s\n", p)
		}
	}

	return nil
}

func (pf *PortForwarder) processNextWorkItem() bool {
	key, quit := pf.wq.Get()
	if quit {
		return false
	}
	defer pf.wq.Done(key)

	err := pf.sync(key.(string))
	if err != nil {
		utilruntime.HandleError(fmt.Errorf("sync %q failed with %v", key, err))
		pf.wq.AddRateLimited(key)
		return true
	}

	pf.wq.Forget(key)
	return true
}

func (pf *PortForwarder) runWorker() {
	for pf.processNextWorkItem() {
	}
}

// Run runs a port forwarder watch loop.
func (pf *PortForwarder) Run(
	ctx context.Context,
) error {
	pf.informer = pf.factory.Controllers().V1alpha1().Proxies().Informer()
	pf.informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(obj)
			if err == nil {
				pf.wq.Add(key)
			}
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			key, err := cache.MetaNamespaceKeyFunc(newObj)
			if err == nil {
				pf.wq.Add(key)
			}
		},
		DeleteFunc: func(obj interface{}) {
			key, err := cache.DeletionHandlingMetaNamespaceKeyFunc(obj)
			if err == nil {
				pf.wq.Add(key)
			}
		},
	})

	stopCh := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
		}
		close(stopCh)
	}()
	pf.factory.Start(stopCh) // Must be called after new informers are added.
	synced := pf.factory.WaitForCacheSync(ctx.Done())
	for v, s := range synced {
		if !s {
			return fmt.Errorf("informer %s failed to sync", v)
		}
	}

	// Run a single worker to not worry about concurrency. It should be fast
	// enough for our use case.
	go wait.Until(pf.runWorker, time.Second, stopCh)

	<-stopCh

	return nil
}
