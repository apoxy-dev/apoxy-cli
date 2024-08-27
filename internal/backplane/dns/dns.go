package dns

import (
	"context"
	"net"
	"time"

	"github.com/buraksezer/olric"
	"github.com/miekg/dns"
)

type Resolver struct {
	dm       olric.DMap
	upstream string

	ctx context.Context
	srv *dns.Server
}

func NewResolver(dm olric.DMap, upstreamAddr string) *Resolver {
	return &Resolver{
		dm:       dm,
		upstream: upstreamAddr,
	}
}

func (r *Resolver) Start(
	ctx context.Context,
	addr string,
) error {
	r.ctx = ctx
	r.srv = &dns.Server{Addr: addr, Net: "udp", Handler: r}
	go func() {
		<-ctx.Done()
		_ = r.srv.Shutdown()
	}()
	return r.srv.ListenAndServe()
}

func (r *Resolver) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	key := req.Question[0].Name
	dmr, err := r.dm.Get(r.ctx, key)
	if err == olric.ErrKeyNotFound {
		fwd := new(dns.Client)
		fwd.Dialer = &net.Dialer{
			Timeout: 2 * time.Second,
		}
		up, _, err := fwd.Exchange(req, r.upstream)
		if err != nil {
			_ = w.WriteMsg(reply(req, key, "", dns.RcodeServerFailure, 0))
			return
		}

		_ = w.WriteMsg(up)
	} else if err != nil {
		_ = w.WriteMsg(reply(req, key, "", dns.RcodeNameError, 0))
		return
	}
	cname, err := dmr.String()
	if err != nil {
		_ = w.WriteMsg(reply(req, key, "", dns.RcodeServerFailure, 0))
		return
	}
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
