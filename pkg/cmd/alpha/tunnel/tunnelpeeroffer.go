package tunnel

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/predicate"

	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
)

type tunnelPeerOfferReconciler struct {
	client.Client

	localTunnelNodeName string
	bind                *wireguard.IceBind
	mu                  sync.Mutex
	peers               map[string]*wireguard.IcePeer
}

func (r *tunnelPeerOfferReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := clog.FromContext(ctx, "name", r.localTunnelNodeName)
	log.Info("Reconciling TunnelPeerOffer")

	var tunnelPeerOffer corev1alpha.TunnelPeerOffer
	if err := r.Get(ctx, req.NamespacedName, &tunnelPeerOffer); err != nil {
		return ctrl.Result{}, client.IgnoreNotFound(err)
	}

	isControlling := true
	var remoteName string
	if tunnelPeerOffer.Spec.RemoteTunnelNodeName == r.localTunnelNodeName {
		isControlling = false
		for _, ref := range tunnelPeerOffer.OwnerReferences {
			if ref.Kind == "TunnelNode" && ref.Controller != nil && *ref.Controller {
				remoteName = ref.Name
				break
			}
		}
		if remoteName == "" {
			return ctrl.Result{}, fmt.Errorf("could not find remote tunnel node name")
		}
		log.Info("Offer controlled by remote node, starting ICE negotiation", "RemotePeer", remoteName)
	} else {
		remoteName = tunnelPeerOffer.Spec.RemoteTunnelNodeName
		log.Info("Offer controlled by local node, starting ICE negotiation", "RemotePeer", remoteName)
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	peer, ok := r.peers[tunnelPeerOffer.Name]
	if ok { // If ICE peer already exists, only update the remote candidates.
		var remoteOffer *corev1alpha.ICEOffer
		if isControlling {
			remoteOffer = tunnelPeerOffer.Status.PeerOffer
		} else {
			remoteOffer = tunnelPeerOffer.Spec.Offer
		}

		if remoteOffer == nil {
			log.Info("ICE offer not yet created")
			return ctrl.Result{}, nil // Will re-trigger when offer is created.
		}

		return r.connect(ctx, remoteName, req, peer, remoteOffer)
	}

	log.Info("Createing a new ICE peer", "IsControlling", false)

	var err error
	peer, err = r.bind.NewPeer(ctx, isControlling)
	if err != nil {
		log.Error(err, "Failed to create ICE peer")
		return ctrl.Result{}, err
	}
	peer.OnCandidate = func(c string) {
		log.Info("ICE candidate", "Candidate", c)
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var tn corev1alpha.TunnelPeerOffer
			if err := r.Get(ctx, req.NamespacedName, &tn); err != nil {
				return err
			}

			ufrag, pwd := peer.LocalUserCredentials()
			cs := peer.LocalCandidates()

			if isControlling {
				tn.Spec.Offer = &corev1alpha.ICEOffer{
					Ufrag:      ufrag,
					Password:   pwd,
					Candidates: cs,
				}
				log.Info("Updating offer spec with local peer's offer", "Spec.Offer.Candidates", tn.Spec.Offer.Candidates)
				return r.Update(ctx, &tn)
			}

			tn.Status.PeerOffer = &corev1alpha.ICEOffer{
				Ufrag:      ufrag,
				Password:   pwd,
				Candidates: cs,
			}
			log.Info("Updating offer status with local peer's offer", "Status.PeerOffer.Candidates", tn.Status.PeerOffer.Candidates)
			return r.Status().Update(ctx, &tn)
		}); err != nil {
			log.Error(err, "Failed to update tunnel peer offer status")
		}
	}
	if err := peer.Init(ctx); err != nil {
		log.Error(err, "Failed to initialize ICE peer")
		return ctrl.Result{}, err
	}

	r.peers[tunnelPeerOffer.Name] = peer

	var remoteOffer *corev1alpha.ICEOffer
	if isControlling {
		remoteOffer = tunnelPeerOffer.Status.PeerOffer
	} else {
		remoteOffer = tunnelPeerOffer.Spec.Offer
	}
	if remoteOffer == nil {
		// If no remote offer, just return and wait for requeue.
		return ctrl.Result{}, nil
	}

	return r.connect(ctx, remoteName, req, peer, remoteOffer)
}

func (r *tunnelPeerOfferReconciler) connect(
	ctx context.Context,
	remoteName string,
	req ctrl.Request,
	peer *wireguard.IcePeer,
	remoteOffer *corev1alpha.ICEOffer,
) (ctrl.Result, error) {
	log := clog.FromContext(ctx)

	if err := peer.AddRemoteOffer(remoteOffer); err != nil {
		log.Error(err, "Failed to add remote candidates")
		return ctrl.Result{}, err
	}

	if err := peer.Connect(ctx, remoteName); err != nil && !errors.Is(err, ice.ErrMultipleStart) {
		log.Error(err, "Failed to connect to ICE peer")

		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var tunnelPeerOffer corev1alpha.TunnelPeerOffer
			if err := r.Get(ctx, req.NamespacedName, &tunnelPeerOffer); err != nil {
				return err
			}
			tunnelPeerOffer.Status.Conditions = append(tunnelPeerOffer.Status.Conditions, metav1.Condition{
				Type:    "Ready",
				Status:  metav1.ConditionFalse,
				Reason:  "ConnectFailed",
				Message: fmt.Sprintf("Peer %s failed to connect: %v", r.localTunnelNodeName, err),
			})
			return r.Status().Update(ctx, &tunnelPeerOffer)
		}); err != nil {
			log.Error(err, "Failed to update tunnel peer offer status")
		}

		// Connect failed, remove the peer and start over in a few seconds.
		log.Info("Connect failed, removing peer and starting over in a few seconds")

		r.mu.Lock()
		delete(r.peers, req.Name)
		r.mu.Unlock()
		peer.Close()

		return ctrl.Result{RequeueAfter: time.Second * 2}, nil
	} else if errors.Is(err, ice.ErrMultipleStart) {
		log.Info("ICE connection already established, ignoring")
		return ctrl.Result{}, nil
	}

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var tunnelPeerOffer corev1alpha.TunnelPeerOffer
		if err := r.Get(ctx, req.NamespacedName, &tunnelPeerOffer); err != nil {
			return err
		}
		tunnelPeerOffer.Status.Conditions = append(tunnelPeerOffer.Status.Conditions, metav1.Condition{
			Type:    "Ready",
			Status:  metav1.ConditionTrue,
			Reason:  "Connected",
			Message: fmt.Sprintf("Peer %s successfully connected", r.localTunnelNodeName),
		})
		return r.Status().Update(ctx, &tunnelPeerOffer)
	}); err != nil {
		log.Error(err, "Failed to update tunnel peer offer status")
	}

	return ctrl.Result{}, nil
}

func (r *tunnelPeerOfferReconciler) makeOfferPredicate() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		if obj == nil {
			return false
		}
		tunnelPeerOffer, ok := obj.(*corev1alpha.TunnelPeerOffer)
		if !ok {
			return false
		}

		// If peer offer targets us, process the event.
		if tunnelPeerOffer.Spec.RemoteTunnelNodeName == r.localTunnelNodeName {
			return true
		}

		// If peer offer is owned by us, process the event.
		if idx := slices.IndexFunc(tunnelPeerOffer.OwnerReferences, func(or metav1.OwnerReference) bool {
			if or.Kind == "TunnelNode" && or.Name == r.localTunnelNodeName {
				return true
			}
			return false
		}); idx >= 0 {
			return true
		}

		return false
	})
}

func (r *tunnelPeerOfferReconciler) setupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha.TunnelPeerOffer{},
			builder.WithPredicates(
				&predicate.ResourceVersionChangedPredicate{},
				r.makeOfferPredicate(),
			),
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
			RecoverPanic:            ptr.To(true),
		}).
		Complete(r)
}
