package kvstore

import (
	"fmt"
	stdlog "log"

	"github.com/hashicorp/go-discover"
	"github.com/hashicorp/go-discover/provider/k8s"
	"github.com/mitchellh/mapstructure"

	"github.com/apoxy-dev/apoxy-cli/pkg/log"
)

type k8sProvider struct {
	d discover.Discover

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
	log.Infof("Initialized k8s provider")
	return nil
}

func (p *k8sProvider) SetLogger(_ *stdlog.Logger) {}

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
	log.Infof("Provider: %s", c.Provider)

	var ok bool
	p.namespace, ok = c.Namespace.(string)
	if !ok {
		return fmt.Errorf("namespace must be a string")
	}
	log.Infof("Namespace: %s", p.namespace)

	p.labelSelector, ok = c.LabelSelector.(string)
	if !ok {
		return fmt.Errorf("labelSelector must be a string")
	}
	log.Infof("LabelSelector: %s", p.labelSelector)

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

type logWriter struct{}

func (w *logWriter) Write(p []byte) (n int, err error) {
	log.Infof(string(p))
	return len(p), nil
}

func (p *k8sProvider) DiscoverPeers() ([]string, error) {
	l := stdlog.New(&logWriter{}, "", 0)
	peers, err := p.d.Addrs(p.getArgs(), l)
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
