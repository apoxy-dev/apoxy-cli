package kvstore

import (
	"fmt"
	stdlog "log"

	"github.com/hashicorp/go-discover"
	"github.com/hashicorp/go-discover/provider/k8s"
	"github.com/mitchellh/mapstructure"
)

type k8sProvider struct {
	d    discover.Discover
	log  *stdlog.Logger
	args map[string]string
}

// NewK8sServiceDiscovery creates a new k8s service discovery plugin.
func NewK8sServiceDiscovery(labelSelector map[string]string) map[string]interface{} {
	return map[string]interface{}{
		"plugin":   &k8sProvider{},
		"provider": "k8s",
		"args":     labelSelector,
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
		Provider string
		Args     interface{}
	}{}
	err := mapstructure.Decode(cfg, &c)
	if err != nil {
		return err
	}
	args, ok := c.Args.(map[string]string)
	if !ok {
		return fmt.Errorf("args must be a map[string]string")
	}
	p.args = args
	return nil
}

func (p *k8sProvider) getArgs() string {
	out := "provider=k8s"
	for key, value := range p.args {
		out += fmt.Sprintf("%s=%s", key, value)
	}
	return out
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
