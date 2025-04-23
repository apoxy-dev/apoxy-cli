package dns

import (
	"context"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/netip"
	"strings"

	"github.com/alphadose/haxmap"
	"github.com/coredns/coredns/plugin"
	"github.com/google/uuid"
	"github.com/miekg/dns"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/util/sets"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	apoxynet "github.com/apoxy-dev/apoxy-cli/pkg/net"
)

// TunnelNodeDNSReconciler reconciles TunnelNode objects and implements CoreDNS plugin.
type TunnelNodeDNSReconciler struct {
	client.Client

	nameCache *haxmap.Map[string, sets.Set[netip.Addr]]
	uuidCache *haxmap.Map[string, sets.Set[netip.Addr]]
}

// NewTunnelNodeDNSReconciler creates a new TunnelNodeDNSReconciler.
func NewTunnelNodeDNSReconciler(client client.Client) *TunnelNodeDNSReconciler {
	return &TunnelNodeDNSReconciler{
		Client:    client,
		nameCache: haxmap.New[string, sets.Set[netip.Addr]](),
		uuidCache: haxmap.New[string, sets.Set[netip.Addr]](),
	}
}

func (r *TunnelNodeDNSReconciler) reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	node := &corev1alpha.TunnelNode{}
	if err := r.Get(ctx, request.NamespacedName, node); apierrors.IsNotFound(err) {
		return reconcile.Result{}, client.IgnoreNotFound(err)
	} else if err != nil {
		return reconcile.Result{}, fmt.Errorf("failed to get TunnelNode: %w", err)
	}

	log := log.FromContext(ctx, "name", node.Name, "uid", node.UID)
	log.Info("Reconciling TunnelNode")

	if !node.DeletionTimestamp.IsZero() {
		r.nameCache.Del(node.Name)
		r.uuidCache.Del(string(node.UID))
		return reconcile.Result{}, nil
	}

	ips := sets.New[netip.Addr]()
	for _, agent := range node.Status.Agents {
		ip, err := netip.ParseAddr(agent.PrivateAddress)
		if err != nil {
			log.Error(err, "Invalid Agent IP address", "addr", agent.PrivateAddress, "agent", agent.Name)
			continue
		}
		if ips.Has(ip) {
			continue
		}
		ips.Insert(ip)
	}

	r.nameCache.Set(node.Name, ips)
	r.uuidCache.Set(string(node.UID), ips)

	return ctrl.Result{}, nil
}

// SetupWithManager sets up the controller with the Manager.
func (r *TunnelNodeDNSReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		Named(r.name()).
		For(&corev1alpha.TunnelNode{}).
		Complete(reconcile.Func(r.reconcile))
}

func (r *TunnelNodeDNSReconciler) name() string { return "tunnel-resolver" }

func (r *TunnelNodeDNSReconciler) serveDNS(ctx context.Context, next plugin.Handler, w dns.ResponseWriter, req *dns.Msg) (int, error) {
	if len(req.Question) == 0 {
		return dns.RcodeSuccess, nil
	}

	log := slog.With(slog.String("qname", req.Question[0].Name))

	qname := req.Question[0].Name
	if !strings.HasSuffix(qname, strings.TrimSuffix(apoxynet.TunnelDomain, ".")+".") {
		log.Debug("Query name does not match TunnelDomain", slog.String("domain_suffix", apoxynet.TunnelDomain))
		return plugin.NextOrFailure(r.name(), next, ctx, w, req)
	}

	name := strings.TrimSuffix(qname, apoxynet.TunnelDomain+".")
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		log.Warn("Empty name")
		return dns.RcodeNameError, nil
	}

	var (
		found bool
		ips   sets.Set[netip.Addr]
	)
	nodeUUID, err := uuid.Parse(name)
	if err == nil {
		ips, found = r.uuidCache.Get(nodeUUID.String())
	} else {
		ips, found = r.nameCache.Get(name)
	}
	if !found {
		log.Warn("Node not found")
		return dns.RcodeNameError, nil
	}

	ipSlice := ips.UnsortedList() // returns a slice copy.
	// Fisher-Yates shuffle to randomize the order of IPs
	for i := len(ips) - 1; i > 0; i-- {
		j := rand.IntN(i + 1)
		ipSlice[i], ipSlice[j] = ipSlice[j], ipSlice[i]
	}

	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true

	for _, ip := range ipSlice {
		var rr dns.RR
		log.Info("Processing IP", slog.String("addr", ip.String()))
		if ip.Is4() && req.Question[0].Qtype == dns.TypeA {
			rr = new(dns.A)
			rr.(*dns.A).Hdr = dns.RR_Header{
				Name:   qname,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    30,
			}
			rr.(*dns.A).A = ip.AsSlice()
		} else if ip.Is6() && req.Question[0].Qtype == dns.TypeAAAA {
			rr = new(dns.AAAA)
			rr.(*dns.AAAA).Hdr = dns.RR_Header{
				Name:   qname,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    30,
			}
			rr.(*dns.AAAA).AAAA = ip.AsSlice()
		} else {
			log.Warn("Invalid IP address", slog.String("addr", ip.String()))
			continue
		}

		msg.Answer = append(msg.Answer, rr)
	}

	if len(msg.Answer) == 0 {
		log.Warn("No valid IP addresses found")
		return dns.RcodeServerFailure, nil
	}

	w.WriteMsg(msg)

	return dns.RcodeSuccess, nil
}

// Resolver returns a plugin.Handler that can be used with the CoreDNS server.
func (r *TunnelNodeDNSReconciler) Resolver(next plugin.Handler) plugin.Handler {
	return plugin.HandlerFunc(func(ctx context.Context, w dns.ResponseWriter, req *dns.Msg) (int, error) {
		code, err := r.serveDNS(ctx, next, w, req)
		if code != dns.RcodeSuccess || err != nil {
			return plugin.NextOrFailure(r.name(), next, ctx, w, req)
		}
		return code, err
	})
}
