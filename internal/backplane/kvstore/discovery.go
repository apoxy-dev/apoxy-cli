package kvstore

import (
	"fmt"
	stdlog "log"

	"github.com/hashicorp/go-discover"
	"github.com/hashicorp/go-discover/provider/k8s"
	"github.com/mitchellh/mapstructure"
)

type k8sProvider struct {
	d   discover.Discover
	log *stdlog.Logger

	namespace     string
	labelSelector string
}

// NewK8sServiceDiscovery creates a new k8s service discovery plugin.
func NewK8sServiceDiscovery(namespace, labelSelector string) map[string]interface{} {
	return map[string]interface{}{
		"plugin":        &k8sProvider{},
		"provider":      "k8s",
		"namespace":     namespace,
		"labelSelector": labelSelector,
	}
}

func (p *k8sProvider) Initialize() error {
	p.d = discover.Discover{
		Providers: map[string]discover.Provider{
			"k8s": &k8s.Provider{},
		},
	}
	p.log.Print("[INFO] Discover initialized")
	return nil
}

func (p *k8sProvider) SetLogger(l *stdlog.Logger) {
	p.log = l
}

func (p *k8sProvider) SetConfig(cfg map[string]interface{}) error {
	c := struct {
		Provider      string
		Namespace     interface{}
		LabelSelector interface{}
	}{}
	err := mapstructure.Decode(cfg, &c)
	if err != nil {
		return err
	}

	if c.Provider != "k8s" {
		return fmt.Errorf("provider must be k8s")
	}
	p.log.Printf("[INFO] Provider: %s", c.Provider)

	var ok bool
	p.namespace, ok = c.Namespace.(string)
	if !ok {
		return fmt.Errorf("namespace must be a string")
	}
	p.log.Printf("[INFO] Namespace: %s", p.namespace)

	p.labelSelector, ok = c.LabelSelector.(string)
	if !ok {
		return fmt.Errorf("labelSelector must be a string")
	}
	p.log.Printf("[INFO] Label selector: %s", p.labelSelector)
	return nil
}

func (p *k8sProvider) getArgs() string {
	args := "provider=k8s"
	if p.namespace != "" {
		args += fmt.Sprintf(` namespace="%s"`, p.namespace)
	}
	if p.labelSelector != "" {
		args += fmt.Sprintf(` label_selector="%s"`, p.labelSelector)
	}
	return args
}

func (p *k8sProvider) DiscoverPeers() ([]string, error) {
	peers, err := p.d.Addrs(p.getArgs(), p.log)
	if err != nil {
		return nil, err
	}
	if len(peers) == 0 {
		return nil, fmt.Errorf("no peer found")
	}
	return peers, nil
}

func (p *k8sProvider) Register() error   { return nil }
func (p *k8sProvider) Deregister() error { return nil }
func (p *k8sProvider) Close() error      { return nil }
