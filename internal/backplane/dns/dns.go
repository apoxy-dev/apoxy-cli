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
	domain := req.Question[0].Name
	dm, err := r.store.CNAMEMap()
	if err != nil {
		log.Errorf("failed to get CNAME map: %v", err)
		_ = w.WriteMsg(replyError(req, dns.RcodeServerFailure))
		return
	}
	dmr, err := dm.Get(r.ctx, domain)
	if err == olric.ErrKeyNotFound {
		log.Debugf("Domain not found in DM. Resolving %s with upstream %s", domain, r.upstream)

		up := new(dns.Client)
		up.Dialer = &net.Dialer{
			Timeout: 2 * time.Second,
		}
		rr, _, err := up.Exchange(req, r.upstream+":53")
		if err != nil {
			log.Errorf("failed to resolve %s with upstream %s: %v", domain, r.upstream, err)
			_ = w.WriteMsg(replyError(req, dns.RcodeServerFailure))
			return
		}

		_ = w.WriteMsg(rr)
		return
	} else if err != nil {
		log.Errorf("failed to get CNAME record for %s: %v", domain, err)
		_ = w.WriteMsg(replyError(req, dns.RcodeNameError))
		return
	}
	val, err := dmr.String()
	if err != nil {
		log.Errorf("failed to parse CNAME record for %s: %v", domain, err)
		_ = w.WriteMsg(replyError(req, dns.RcodeServerFailure))
		return
	}

	ttl := int(time.Duration(dmr.TTL()) / time.Second)
	if ttl == 0 {
		ttl = 60
	}

	_, ok := dns.IsDomainName(val)
	if !ok {
		rrVal := net.ParseIP(val)
		if rrVal == nil {
			log.Errorf("invalid RR value (not IP or domain): %s", val)
			_ = w.WriteMsg(replyError(req, dns.RcodeServerFailure))
			return
		}
		// val is an IP address
		log.Debugf("Resolved %s to A %s", domain, rrVal)

		_ = w.WriteMsg(replyA(req, domain, rrVal, ttl))
		return
	}

	// val is a domain name - CNAME resolution (only one level).
	log.Debugf("Resolved %s to CNAME %s", domain, val)
	up := new(dns.Client)
	up.Dialer = &net.Dialer{
		Timeout: 2 * time.Second,
	}
	areq := new(dns.Msg)
	areq.SetQuestion(val, dns.TypeA)
	rr, _, err := up.Exchange(areq, r.upstream+":53")
	if err != nil {
		log.Errorf("failed to resolve %s with upstream %s: %v", domain, r.upstream, err)
		_ = w.WriteMsg(replyError(req, dns.RcodeServerFailure))
		return
	}
	var vals []net.IP
	for _, a := range rr.Answer {
		if a.Header().Rrtype == dns.TypeA {
			log.Debugf("Resolved CNAME %s to A %s", val, a.(*dns.A).A)
			vals = append(vals, a.(*dns.A).A)
			break
		}
	}
	if len(vals) == 0 {
		log.Errorf("failed to resolve CNAME %s to A record", val)
		_ = w.WriteMsg(replyError(req, dns.RcodeServerFailure))
		return
	}

	_ = w.WriteMsg(replyCNAME(req, domain, val, vals, ttl))
}

func replyError(req *dns.Msg, rcode int) *dns.Msg {
	resp := &dns.Msg{}
	resp.SetRcode(req, rcode)
	return resp
}

func replyA(req *dns.Msg, domain string, val net.IP, ttl int) *dns.Msg {
	resp := &dns.Msg{}
	resp.SetReply(req)
	resp.Answer = append(resp.Answer, &dns.A{
		Hdr: dns.RR_Header{
			Name:   domain,
			Rrtype: dns.TypeA,
			Class:  dns.ClassINET,
			Ttl:    uint32(ttl),
		},
		A: val,
	})
	return resp
}

func replyCNAME(req *dns.Msg, domain, cname string, vals []net.IP, ttl int) *dns.Msg {
	resp := &dns.Msg{}
	resp.SetReply(req)
	resp.Answer = append(resp.Answer, &dns.CNAME{
		Hdr: dns.RR_Header{
			Name:   domain,
			Rrtype: dns.TypeCNAME,
			Class:  dns.ClassINET,
			Ttl:    uint32(ttl),
		},
		Target: cname,
	})
	for _, val := range vals {
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   cname,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    uint32(ttl),
			},
			A: val,
		})
	}
	return resp
}
