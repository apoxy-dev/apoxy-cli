package dns

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"time"

	"github.com/coredns/coredns/plugin"
	"github.com/docker/docker/libnetwork/resolvconf"
	"github.com/docker/docker/libnetwork/types"
	mdns "github.com/miekg/dns"

	"github.com/apoxy-dev/apoxy-cli/pkg/log"
)

const (
	upstreamPort = 53
)

// upstream is a plugin that sends queries to a random upstream.
type upstream struct {
	Next      plugin.Handler
	Upstreams []string
}

// Name implements the plugin.Handler interface.
func (u *upstream) Name() string { return "upstream" }

// ServeDNS implements the plugin.Handler interface.
func (u *upstream) ServeDNS(ctx context.Context, w mdns.ResponseWriter, r *mdns.Msg) (int, error) {
	log.Debugf("upstream.ServeDNS: %v", r.Question)
	if len(u.Upstreams) == 0 {
		log.Debugf("no upstreams, using next")
		return u.Next.ServeDNS(ctx, w, r)
	}

	upstream := u.Upstreams[rand.Intn(len(u.Upstreams))]

	log.Debugf("using upstream %v:%d", upstream, upstreamPort)

	client := &mdns.Client{}
	client.Dialer = &net.Dialer{
		Timeout: 2 * time.Second,
	}
	r.RecursionDesired = true

	response, _, err := client.Exchange(r, fmt.Sprintf("%v:%d", upstream, upstreamPort))
	if err != nil {
		log.Debugf("failed to exchange: %v", err)
		return mdns.RcodeServerFailure, err
	}

	w.WriteMsg(response)
	return mdns.RcodeSuccess, nil
}

// LoadResolvConf loads system resolv.conf and sets the upstreams.
func (u *upstream) LoadResolvConf() error {
	r, err := resolvconf.Get()
	if err != nil {
		return fmt.Errorf("failed to get resolvconf: %v", err)
	}
	u.Upstreams = resolvconf.GetNameservers(r.Content, types.IPv4)
	if len(u.Upstreams) == 0 {
		return fmt.Errorf("no nameservers found in resolvconf")
	}
	log.Infof("Using upstreams: %v", u.Upstreams)
	return nil
}
