package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/buraksezer/olric"
	"github.com/docker/docker/libnetwork/resolvconf"
	"github.com/docker/docker/libnetwork/types"
	"github.com/miekg/dns"

	"github.com/apoxy-dev/apoxy-cli/internal/backplane/kvstore"
	"github.com/apoxy-dev/apoxy-cli/internal/log"
)

type Resolver struct {
	store *kvstore.Store

	ctx      context.Context
	upstream string
	srv      *dns.Server
}

func NewResolver(store *kvstore.Store) *Resolver {
	return &Resolver{
		store: store,
	}
}

func detectUpstream() (string, error) {
	upstream := []string{}
	if r, err := resolvconf.Get(); err == nil {
		upstream = resolvconf.GetNameservers(r.Content, types.IPv4)
	}
	if len(upstream) == 0 {
		return "", fmt.Errorf("no upstream DNS servers found")
	}
	return upstream[0], nil
}

func (r *Resolver) Start(
	ctx context.Context,
	addr string,
) error {
	r.ctx = ctx
	var err error
	r.upstream, err = detectUpstream()
	if err != nil {
		return fmt.Errorf("failed to detect upstream DNS server: %v", err)
	}

	r.srv = &dns.Server{Addr: addr, Net: "udp", Handler: r}
	go func() {
		<-ctx.Done()
		_ = r.srv.Shutdown()
	}()
	log.Infof("Starting DNS resolver on %s", addr)
	return r.srv.ListenAndServe()
}

func (r *Resolver) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	key := req.Question[0].Name
	dm, err := r.store.CNAMEMap()
	if err != nil {
		log.Errorf("failed to get CNAME map: %v", err)
		_ = w.WriteMsg(reply(req, key, "", dns.RcodeServerFailure, 0))
		return
	}
	dmr, err := dm.Get(r.ctx, key)
	if err == olric.ErrKeyNotFound {
		log.Debugf("Domain not found in DM. Resolving %s with upstream %s", key, r.upstream)

		fwd := new(dns.Client)
		fwd.Dialer = &net.Dialer{
			Timeout: 2 * time.Second,
		}
		up, _, err := fwd.Exchange(req, r.upstream+":53")
		if err != nil {
			log.Errorf("failed to resolve %s with upstream %s: %v", key, r.upstream, err)
			_ = w.WriteMsg(reply(req, key, "", dns.RcodeServerFailure, 0))
			return
		}

		_ = w.WriteMsg(up)
		return
	} else if err != nil {
		log.Errorf("failed to get CNAME record for %s: %v", key, err)
		_ = w.WriteMsg(reply(req, key, "", dns.RcodeNameError, 0))
		return
	}
	cname, err := dmr.String()
	if err != nil {
		log.Errorf("failed to parse CNAME record for %s: %v", key, err)
		_ = w.WriteMsg(reply(req, key, "", dns.RcodeServerFailure, 0))
		return
	}

	log.Debugf("Resolved %s to %s", key, cname)

	_ = w.WriteMsg(reply(req, key, cname, dns.RcodeSuccess, int(time.Duration(dmr.TTL())/time.Second)))
}

func reply(req *dns.Msg, domain, cname string, rcode, ttl int) *dns.Msg {
	resp := &dns.Msg{}
	resp.SetRcode(req, rcode)
	if rcode != dns.RcodeSuccess {
		return resp
	}
	resp.Answer = append(resp.Answer, &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   domain,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    uint32(ttl),
		},
		Target: cname,
	})
	return resp
}
