package tunnel

import (
	"context"
	goerrors "errors"
	"fmt"
	"slices"
	"sync"

	"github.com/pion/ice/v4"
	"k8s.io/apimachinery/pkg/api/errors"
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

func getOfferOwner(ctx context.Context, client client.Client, offer *corev1alpha.TunnelPeerOffer) (string, error) {
	ownerRef := metav1.GetControllerOf(offer)
	if ownerRef == nil {
		return "", fmt.Errorf("could not find owner reference")
	}
	if ownerRef.Kind != "TunnelNode" {
		return "", fmt.Errorf("owner reference is not a TunnelPeer")
	}
	return ownerRef.Name, nil
}

func (r *tunnelPeerOfferReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := clog.FromContext(ctx, "name", r.localTunnelNodeName)
	log.Info("Reconciling TunnelPeerOffer")

	tunnelPeerOffer := &corev1alpha.TunnelPeerOffer{}
	if err := r.Get(ctx, req.NamespacedName, tunnelPeerOffer); client.IgnoreNotFound(err) != nil {
		return ctrl.Result{}, err
	} else if errors.IsNotFound(err) {
		remoteName := req.Name
		r.mu.Lock()
		if peer, ok := r.peers[remoteName]; ok {
			peer.Close()
			delete(r.peers, remoteName)
			log.Info("Deleted TunnelPeerOffer")
		}
		r.mu.Unlock()

		return ctrl.Result{}, nil
	}

	if tunnelPeerOffer.Spec.RemoteTunnelNodeName == r.localTunnelNodeName { // Remote offer.
		switch tunnelPeerOffer.Status.Phase {
		case corev1alpha.TunnelPeerOfferPhaseConnected:
			log.Info("Already connected, ignoring")
			return ctrl.Result{}, nil
		case corev1alpha.TunnelPeerOfferPhaseFailed:
			log.Info("Remote peer offer is in failed, ignoring")
			return ctrl.Result{}, nil
		case corev1alpha.TunnelPeerOfferPhaseConnecting:
			remoteName, err := getOfferOwner(ctx, r.Client, tunnelPeerOffer)
			if err != nil {
				return ctrl.Result{}, err
			}

			log.Info("Offer controlled by remote node, starting ICE negotiation", "RemotePeer", remoteName)

			r.mu.Lock()
			defer r.mu.Unlock()
			peer, ok := r.peers[remoteName]
			if !ok { // Haven't started our end of the ICE negotiation yet.
				return ctrl.Result{Requeue: true}, nil
			}

			remoteOffer := tunnelPeerOffer.Spec.Offer
			if remoteOffer == nil {
				log.Info("ICE offer not yet created")
				return ctrl.Result{}, nil // Will re-trigger when offer is created.
			}

			log.Info("Connecting to remote peer", "RemotePeer", remoteName)

			return r.connect(ctx, remoteName, req, peer, remoteOffer)
		default:
			log.Info("Remote offer is in unknown state, ignoring")
			return ctrl.Result{}, nil
		}
	}

	remoteName := tunnelPeerOffer.Spec.RemoteTunnelNodeName
	log.Info("Offer controlled by local node", "RemotePeer", remoteName)

	r.mu.Lock()
	defer r.mu.Unlock()
	peer, ok := r.peers[remoteName]
	if ok {
		switch tunnelPeerOffer.Status.Phase {
		case corev1alpha.TunnelPeerOfferPhaseConnected, corev1alpha.TunnelPeerOfferPhaseConnecting:
			return ctrl.Result{}, nil // Already connected, or connecting, just return.
		case corev1alpha.TunnelPeerOfferPhaseFailed:
			log.Info("Failed state, cleaning up peer")
			peer.Close()
			delete(r.peers, remoteName)
			return ctrl.Result{}, nil
		default:
			return ctrl.Result{}, nil
		}
	}

	log.Info("Starting ICE negotiation", "RemotePeer", remoteName)

	var err error
	isControlling := r.localTunnelNodeName > remoteName
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

			tn.Spec.Offer = &corev1alpha.ICEOffer{
				Ufrag:      ufrag,
				Password:   pwd,
				Candidates: cs,
			}
			log.Info("Updating offer spec with local peer's offer", "Spec.Offer.Candidates", tn.Spec.Offer.Candidates)
			return r.Update(ctx, &tn)
		}); err != nil {
			log.Error(err, "Failed to update tunnel peer offer status")
		}
	}
	peer.OnConnected = func() {
		log.Info("ICE connection established")
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var tn corev1alpha.TunnelPeerOffer
			if err := r.Get(ctx, req.NamespacedName, &tn); err != nil {
				return err
			}
			tn.Status.Conditions = append(tn.Status.Conditions, metav1.Condition{
				Type:               "Connected",
				Status:             metav1.ConditionTrue,
				Reason:             "IceConnected",
				LastTransitionTime: metav1.Now(),
			})
			tn.Status.Phase = corev1alpha.TunnelPeerOfferPhaseConnected
			return r.Status().Update(ctx, &tn)
		}); err != nil {
			log.Error(err, "Failed to update tunnel peer offer status")
		}
	}
	peer.OnDisconnected = func(msg string) {
		log.Info("ICE connection disconnected", "Reason", msg)
		if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
			var tn corev1alpha.TunnelPeerOffer
			if err := r.Get(ctx, req.NamespacedName, &tn); err != nil {
				return err
			}
			tn.Status.Phase = corev1alpha.TunnelPeerOfferPhaseFailed
			tn.Status.Conditions = append(tn.Status.Conditions, metav1.Condition{
				Type:               "ICEConnected",
				Status:             metav1.ConditionFalse,
				Reason:             "Failed",
				Message:            fmt.Sprintf("Peer %s failed to connect: %v", remoteName, msg),
				LastTransitionTime: metav1.Now(),
			})
			return r.Status().Update(ctx, &tn)
		}); err != nil {
			log.Error(err, "Failed to update tunnel peer offer status")
		}
	}
	if err := peer.Init(ctx); err != nil {
		log.Error(err, "Failed to initialize ICE peer")
		peer.Close()
		return ctrl.Result{}, err
	}

	r.peers[remoteName] = peer

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		var tn corev1alpha.TunnelPeerOffer
		if err := r.Get(ctx, req.NamespacedName, &tn); err != nil {
			return err
		}
		tn.Status.Phase = corev1alpha.TunnelPeerOfferPhaseConnecting
		return r.Status().Update(ctx, &tn)
	}); err != nil {
		log.Error(err, "Failed to update tunnel peer offer status")
	}

	return ctrl.Result{}, nil // Wait until the remote offer is created.
}

func (r *tunnelPeerOfferReconciler) connect(
	ctx context.Context,
	remoteName string,
	req ctrl.Request,
	peer *wireguard.IcePeer,
	remoteOffer *corev1alpha.ICEOffer,
) (ctrl.Result, error) {
	log := clog.FromContext(ctx)

	if remoteOffer == nil {
		log.Info("ICE offer not yet created")
		return ctrl.Result{}, nil // Will re-trigger when offer is created.
	}

	if err := peer.AddRemoteOffer(remoteOffer); err != nil {
		log.Error(err, "Failed to add remote candidates")
		return ctrl.Result{}, err
	}

	go func() {
		if err := peer.Connect(ctx, remoteName); err != nil && !goerrors.Is(err, ice.ErrMultipleStart) {
			log.Error(err, "Failed to connect to ICE peer")

			if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
				var tunnelPeerOffer corev1alpha.TunnelPeerOffer
				if err := r.Get(ctx, req.NamespacedName, &tunnelPeerOffer); err != nil {
					return err
				}
				tunnelPeerOffer.Status.Phase = corev1alpha.TunnelPeerOfferPhaseFailed
				tunnelPeerOffer.Status.Conditions = append(tunnelPeerOffer.Status.Conditions, metav1.Condition{
					Type:               "Connected",
					Status:             metav1.ConditionFalse,
					Reason:             "Failed",
					Message:            fmt.Sprintf("Peer %s failed to connect: %v", r.localTunnelNodeName, err),
					LastTransitionTime: metav1.Now(),
				})
				return r.Status().Update(ctx, &tunnelPeerOffer)
			}); err != nil {
				log.Error(err, "Failed to update tunnel peer offer status")
			}

			// Connect failed, remove the peer and start over in a few seconds.
			log.Info("Connect failed, removing peer and starting over in a few seconds")

			r.mu.Lock()
			delete(r.peers, remoteName)
			r.mu.Unlock()
			peer.Close()

			return
		} else if goerrors.Is(err, ice.ErrMultipleStart) {
			log.Info("ICE connection already established, ignoring")
			return
		}
	}()

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
