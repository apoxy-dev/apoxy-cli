package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	icelogging "github.com/pion/logging"
	"github.com/pion/stun/v3"
	"github.com/spf13/cobra"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"k8s.io/utils/set"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	clog "sigs.k8s.io/controller-runtime/pkg/log"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	"github.com/apoxy-dev/apoxy-cli/client/versioned"
	"github.com/apoxy-dev/apoxy-cli/config"
	"github.com/apoxy-dev/apoxy-cli/pkg/log"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"

	configv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/config/v1alpha1"
	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
)

const (
	matchingTunnelNodesIndex = "remoteTunnelNodeIndex"

	tunnelNodeEpochLabel = "core.apoxy.dev/tunnelnode-epoch"
)

var (
	scheme       = runtime.NewScheme()
	codecFactory = serializer.NewCodecFactory(scheme)
	decodeFn     = codecFactory.UniversalDeserializer().Decode
)

func init() {
	utilruntime.Must(corev1alpha.Install(scheme))
}

var tunnelNodeName string

var tunnelRunCmd = &cobra.Command{
	Use:   "run",
	Short: "Run a tunnel",
	Long:  "Create a secure tunnel to the remote Apoxy Edge fabric.",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx := cmd.Context()
		cmd.SilenceUsage = true

		cfg, err := config.Load()
		if err != nil {
			return fmt.Errorf("unable to load config: %w", err)
		}

		a3y, err := config.DefaultAPIClient()
		if err != nil {
			return fmt.Errorf("unable to create API client: %w", err)
		}

		var tn *corev1alpha.TunnelNode
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			if tunnelNodeFile != "" {
				return fmt.Errorf("cannot use --file with stdin")
			}
			tn, err = loadTunnelNodeFromStdin()
		} else if tunnelNodeFile != "" {
			tn, err = loadTunnelNodeFromPath(tunnelNodeFile)
			// Clean up the tunnel node after the command completes.
			defer func() {
				slog.Debug("Deleting TunnelNode", slog.String("name", tn.Name))

				if err := a3y.CoreV1alpha().TunnelNodes().Delete(ctx, tn.Name, metav1.DeleteOptions{}); err != nil {
					log.Errorf("Failed to delete TunnelNode: %v", err)
				}
			}()
		} else if tunnelNodeName != "" {
			tn, err = a3y.CoreV1alpha().TunnelNodes().Get(ctx, tunnelNodeName, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("unable to get TunnelNode: %w", err)
			}
		} else {
			return fmt.Errorf("either --file or stdin must be specified")
		}
		if err != nil {
			return fmt.Errorf("unable to get TunnelNode: %w", err)
		}

		iceConf := &ice.AgentConfig{
			// TODO(dsky): Support TCP network types and other configs from TunnelConfig.
			NetworkTypes:  []ice.NetworkType{ice.NetworkTypeUDP4, ice.NetworkTypeTCP4},
			CheckInterval: ptr.To(50 * time.Millisecond),
			CandidateTypes: []ice.CandidateType{
				ice.CandidateTypeHost,
				ice.CandidateTypeServerReflexive,
				ice.CandidateTypePeerReflexive,
				ice.CandidateTypeRelay,
			},
			LoggerFactory: &icelogging.DefaultLoggerFactory{
				Writer: log.NewDefaultLogWriter(log.InfoLevel),
			},
		}
		for _, uri := range cfg.Tunnel.STUNServers {
			proto := stun.NewProtoType(string(uri.Proto))
			if proto == stun.ProtoTypeUnknown {
				log.Errorf("Unknown STUN protocol: %s", uri.Proto)
				return fmt.Errorf("unknown STUN protocol: %s", uri.Proto)
			}
			iceConf.Urls = append(iceConf.Urls, &stun.URI{
				Scheme:   stun.SchemeTypeSTUN,
				Host:     uri.Host,
				Port:     uri.Port,
				Username: uri.Username,
				Password: uri.Password,
				Proto:    proto,
			})
		}
		if len(iceConf.Urls) == 0 {
			iceConf.Urls = append(iceConf.Urls, &stun.URI{
				Scheme: stun.SchemeTypeSTUN,
				Host:   "stun.l.google.com",
				Port:   19302,
			})
		}

		log.Infof("Creating TunnelNode %s", tn.Name)

		tun := &tunnelNodeReconciler{
			scheme:          scheme,
			localTunnelNode: *tn,
			cfg:             cfg,
			a3y:             a3y,
			bind:            wireguard.NewIceBind(ctx, iceConf),
		}
		return tun.run(ctx)
	},
}

type tunnelNodeReconciler struct {
	client.Client

	mu              sync.RWMutex
	localTunnelNode corev1alpha.TunnelNode

	scheme *runtime.Scheme
	cfg    *configv1alpha1.Config
	a3y    versioned.Interface
	bind   *wireguard.IceBind

	tun tunnel.Tunnel
}

func (t *tunnelNodeReconciler) run(ctx context.Context) error {
	var err error

	tunAddr := tunnel.NewApoxy4To6Prefix(t.cfg.CurrentProject, t.localTunnelNode.Name)
	if t.cfg.Tunnel != nil && t.cfg.Tunnel.Mode == configv1alpha1.TunnelModeUserspace {
		socksPort := uint16(1080)
		if t.cfg.Tunnel.SocksPort != nil {
			socksPort = uint16(*t.cfg.Tunnel.SocksPort)
		}

		t.tun, err = tunnel.CreateUserspaceTunnel(ctx, tunAddr.Addr(), t.bind, socksPort, t.cfg.Tunnel.PacketCapturePath, t.cfg.Verbose)
	} else {
		t.tun, err = tunnel.CreateKernelTunnel(ctx, tunAddr, tunnel.DefaultSTUNServers)
	}
	if err != nil {
		return fmt.Errorf("unable to create tunnel: %w", err)
	}
	defer t.tun.Close()

	slog.Debug("Running TunnelNode controller",
		slog.String("name", t.localTunnelNode.Name), slog.String("publicKey", t.tun.PublicKey()),
		slog.String("internalAddress", t.tun.InternalAddress().String()))

	client, err := config.DefaultAPIClient()
	if err != nil {
		return fmt.Errorf("unable to create API client: %w", err)
	}

	t.localTunnelNode.Status.Phase = corev1alpha.NodePhaseReady
	t.localTunnelNode.Status.PublicKey = t.tun.PublicKey()
	t.localTunnelNode.Status.ExternalAddress = t.tun.ExternalAddress().String()
	t.localTunnelNode.Status.InternalAddress = t.tun.InternalAddress().String()

	// Create/update the TunnelNode object in the API.
	slog.Debug("Creating/updating TunnelNode", slog.String("name", t.localTunnelNode.Name))

	if err := t.upsertTunnelNode(ctx, client, 10*time.Second); err != nil {
		log.Errorf("Failed to create/update TunnelNode: %v", err)
		return err
	}

	log.Infof("Starting tunnel node controller")

	mgr, err := ctrl.NewManager(client.RESTConfig, ctrl.Options{
		Scheme:         scheme,
		LeaderElection: false,
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
	})
	if err != nil {
		return fmt.Errorf("unable to set up overall controller manager: %w", err)
	}

	t.Client = mgr.GetClient()
	if err := t.setupWithManager(ctx, mgr); err != nil {
		return fmt.Errorf("unable to set up controller: %w", err)
	}
	tunnelOfferCtrl := &tunnelPeerOfferReconciler{
		Client:              mgr.GetClient(),
		localTunnelNodeName: t.localTunnelNode.Name,
		bind:                t.bind,
		peers:               make(map[string]*wireguard.IcePeer),
	}
	if err := tunnelOfferCtrl.setupWithManager(mgr); err != nil {
		return fmt.Errorf("unable to set up controller: %w", err)
	}

	doneCh := make(chan struct{})
	go func() {
		defer close(doneCh)
		if err := mgr.Start(ctx); err != nil {
			slog.Error("Manager exited non-zero", slog.Any("error", err))
		}
	}()
	go t.runSyncLoop(ctx, client)

	// Set the initial status of the TunnelNode object.
	// Wait for the TunnelNode object to be deleted, or for the command to be cancelled.
	select {
	case <-doneCh:
	case <-ctx.Done():
	}

	return nil
}

func (t *tunnelNodeReconciler) makeTunnelNodePredicate() predicate.Predicate {
	return predicate.NewPredicateFuncs(func(obj client.Object) bool {
		tunnelNode, ok := obj.(*corev1alpha.TunnelNode)
		if !ok {
			return false
		}
		t.mu.RLock()
		defer t.mu.RUnlock()
		if tunnelNode.Name != t.localTunnelNode.Name {
			return true
		}
		for _, peer := range t.localTunnelNode.Spec.Peers {
			if peer.TunnelNodeRef != nil && peer.TunnelNodeRef.Name == tunnelNode.Name {
				return true
			}
			if peer.LabelSelector != nil {
				selector, err := metav1.LabelSelectorAsSelector(peer.LabelSelector)
				if err != nil {
					slog.Warn("Invalid label selector", slog.Any("error", err))
					continue
				}
				if selector.Matches(labels.Set(tunnelNode.Labels)) {
					return true
				}
			}
		}
		return false
	})
}

func (t *tunnelNodeReconciler) setupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	if err := mgr.GetFieldIndexer().IndexField(ctx, &corev1alpha.TunnelNode{}, matchingTunnelNodesIndex, func(obj client.Object) []string {
		remoteNode, ok := obj.(*corev1alpha.TunnelNode)
		if !ok {
			return nil
		}
		t.mu.RLock()
		defer t.mu.RUnlock()
		for _, peer := range t.localTunnelNode.Spec.Peers {
			if peer.TunnelNodeRef != nil && peer.TunnelNodeRef.Name == remoteNode.Name {
				return []string{"true"}
			}
			if peer.LabelSelector != nil {
				selector, err := metav1.LabelSelectorAsSelector(peer.LabelSelector)
				if err != nil {
					slog.Warn("Invalid label selector", slog.Any("error", err))
					continue
				}
				if selector.Matches(labels.Set(remoteNode.Labels)) {
					return []string{"true"}
				}
			}
		}
		return nil
	}); err != nil {
		return fmt.Errorf("unable to create index for remoteTunnelNodeIndex: %w", err)
	}
	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha.TunnelNode{},
			builder.WithPredicates(
				&predicate.ResourceVersionChangedPredicate{},
				t.makeTunnelNodePredicate(),
			),
		).
		Watches(
			&corev1alpha.TunnelPeerOffer{},
			handler.EnqueueRequestsFromMapFunc(func(_ context.Context, obj client.Object) []reconcile.Request {
				offer, ok := obj.(*corev1alpha.TunnelPeerOffer)
				if !ok {
					return nil
				}
				if len(offer.GetOwnerReferences()) == 0 {
					return nil
				}
				return []reconcile.Request{{
					NamespacedName: types.NamespacedName{
						Name: offer.GetOwnerReferences()[0].Name,
					},
				}}
			}),
			builder.WithPredicates(predicate.ResourceVersionChangedPredicate{}),
		).
		WithOptions(controller.Options{
			MaxConcurrentReconciles: 1,
			RecoverPanic:            ptr.To(true),
		}).
		Complete(t)
}

func (t *tunnelNodeReconciler) matchWithRemotePeer(
	ctx context.Context,
	remote *corev1alpha.TunnelNode,
) (bool, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	for _, peer := range remote.Spec.Peers {
		if peer.TunnelNodeRef != nil {
			if peer.TunnelNodeRef.Name == t.localTunnelNode.Name {
				return true, nil
			}
		} else if peer.LabelSelector != nil {
			// Re-fetch local TunnelNode object from the index.
			var localTunnelNode corev1alpha.TunnelNode
			if err := t.Get(ctx, client.ObjectKey{Name: t.localTunnelNode.Name}, &localTunnelNode); err != nil {
				return false, err
			}
			selector, err := metav1.LabelSelectorAsSelector(peer.LabelSelector)
			if err != nil {
				slog.Warn("Invalid label selector", slog.Any("error", err))
				continue
			}

			if selector.Matches(labels.Set(localTunnelNode.Labels)) {
				return true, nil
			}
		}
	}
	return false, nil
}

func (t *tunnelNodeReconciler) getMatchingRemoteTunnelNodes(
	ctx context.Context,
	localTunnelNode *corev1alpha.TunnelNode,
) (map[string]*corev1alpha.TunnelNode, error) {
	matchingNodes := &corev1alpha.TunnelNodeList{}
	if err := t.List(ctx, matchingNodes, client.MatchingFields{matchingTunnelNodesIndex: "true"}); err != nil {
		return nil, fmt.Errorf("unable to list matching TunnelNodes: %w", err)
	}

	matchingTunnelNodes := make(map[string]*corev1alpha.TunnelNode)
	for i := range matchingNodes.Items {
		node := &matchingNodes.Items[i]
		matchingTunnelNodes[node.Status.PublicKey] = node
	}

	return matchingTunnelNodes, nil
}

func isConnected(offer *corev1alpha.TunnelPeerOffer) bool {
	if offer == nil {
		return false
	}
	return offer.Status.Phase == corev1alpha.TunnelPeerOfferPhaseConnected
}

func (t *tunnelNodeReconciler) offerPeer(
	ctx context.Context,
	peerTunnelNode *corev1alpha.TunnelNode,
) (*corev1alpha.TunnelPeerOffer, bool, error) {
	offerName := fmt.Sprintf("%s-%s-%d", t.localTunnelNode.Name, peerTunnelNode.Name, *&t.localTunnelNode.Status.Epoch)
	// Check if offer already exists
	existingOffer := &corev1alpha.TunnelPeerOffer{}
	if err := t.Get(ctx, client.ObjectKey{Name: offerName}, existingOffer); err == nil {
		return existingOffer, isConnected(existingOffer), nil
	} else if !apierrors.IsNotFound(err) {
		return nil, false, err
	}

	peerOffer := &corev1alpha.TunnelPeerOffer{
		ObjectMeta: metav1.ObjectMeta{
			Name: offerName,
			Labels: map[string]string{
				tunnelNodeEpochLabel: strconv.FormatInt(t.localTunnelNode.Status.Epoch, 10),
			},
		},
		Spec: corev1alpha.TunnelPeerOfferSpec{
			RemoteTunnelNodeName: peerTunnelNode.Name,
		},
	}
	if err := controllerutil.SetControllerReference(&t.localTunnelNode, peerOffer, t.scheme); err != nil {
		slog.Error("Failed to set controller reference", slog.Any("error", err))
		return nil, false, err
	}
	if err := t.Create(ctx, peerOffer); err != nil && !apierrors.IsAlreadyExists(err) {
		slog.Error("Failed to create TunnelPeerOffer", slog.String("name", peerOffer.Name), slog.Any("error", err))
		return nil, false, err
	}
	return peerOffer, isConnected(peerOffer), nil
}

func (t *tunnelNodeReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	log := clog.FromContext(ctx)

	var tunnelNode corev1alpha.TunnelNode
	if err := t.Get(ctx, req.NamespacedName, &tunnelNode); err != nil {
		log.Error(err, "Failed to get TunnelNode")
		return ctrl.Result{}, err
	}

	t.mu.RLock()
	isLocal := tunnelNode.Name == t.localTunnelNode.Name
	log.Info("Reconciling", "isLocal", isLocal, "localTunnelNode", t.localTunnelNode.Name, "remoteTunnelNode", tunnelNode.Name)
	if isLocal { // Local tunnel peer - do nothing.
		t.mu.RUnlock()
		t.mu.Lock()
		t.localTunnelNode = *tunnelNode.DeepCopy()
		t.mu.Unlock()
		return ctrl.Result{}, nil
	}
	defer t.mu.RUnlock()

	remoteTunnelNodes, err := t.getMatchingRemoteTunnelNodes(ctx, &tunnelNode)
	remotePeerPublicKeys := set.New[string]()
	for _, remoteTunnelNode := range remoteTunnelNodes {
		if remoteTunnelNode.Status.Phase == corev1alpha.NodePhaseReady &&
			remoteTunnelNode.Status.PublicKey != "" {
			remotePeerPublicKeys.Insert(remoteTunnelNode.Status.PublicKey)
		}
	}
	slog.Debug("Remote peers", slog.Any("publicKeys", remotePeerPublicKeys.SortedList()))

	knownPeers, err := t.tun.Peers()
	if err != nil {
		slog.Error("Failed to get known peers", slog.Any("error", err))
		return ctrl.Result{}, err
	}

	knownPeerPublicKeys := set.New[string]()
	var peerIPs []any
	for _, peerConf := range knownPeers {
		knownPeerPublicKeys.Insert(*peerConf.PublicKey)
		peerIPs = append(peerIPs, slog.Any(*peerConf.PublicKey, peerConf.AllowedIPs))
	}
	slog.Debug("Known peers", peerIPs...)

	// Check for peers with no longer valid configurations.
	for _, peerConf := range knownPeers {
		peerTunnelNode, ok := remoteTunnelNodes[*peerConf.PublicKey]
		if !ok {
			continue
		}

		// Check if the peer configuration has changed.
		var peerConfChanged bool

		if (len(peerConf.AllowedIPs) == 0 && peerTunnelNode.Status.InternalAddress != "") ||
			(len(peerConf.AllowedIPs) > 0 && peerConf.AllowedIPs[0] != peerTunnelNode.Status.InternalAddress) {
			peerConfChanged = true
		}

		if peerConfChanged {
			slog.Debug("Peer configuration changed", slog.String("name", peerTunnelNode.Name))

			if err := t.tun.RemovePeer(*peerConf.PublicKey); err != nil {
				slog.Error("Failed to remove peer", slog.String("name", peerTunnelNode.Name), slog.Any("error", err))
			}

			// Will be re-added below with the new configuration.
			knownPeerPublicKeys.Delete(*peerConf.PublicKey)
		}
	}

	// New peers to add.
	for peerPublicKey := range remotePeerPublicKeys.Difference(knownPeerPublicKeys) {
		peerTunnelNode := remoteTunnelNodes[peerPublicKey]

		slog.Debug("Adding peer",
			slog.String("name", peerTunnelNode.Name),
			slog.String("publicKey", peerPublicKey),
			slog.String("internalAddress", peerTunnelNode.Status.InternalAddress))

		_, isConnected, err := t.offerPeer(ctx, peerTunnelNode)
		if err != nil {
			slog.Error("Failed to offer peer", slog.String("name", peerTunnelNode.Name), slog.Any("error", err))
			continue
		}
		if !isConnected {
			slog.Debug("TunnelPeerOffer not yet connected", slog.String("name", peerTunnelNode.Name))
			continue
		}

		peerConf := &wireguard.PeerConfig{
			PublicKey:  ptr.To(peerTunnelNode.Status.PublicKey),
			AllowedIPs: []string{peerTunnelNode.Status.InternalAddress},
			Endpoint:   ptr.To(peerTunnelNode.Name),
		}

		if err := t.tun.AddPeer(peerConf); err != nil {
			slog.Error("Failed to add peer", slog.String("name", peerTunnelNode.Name), slog.Any("error", err))
			return ctrl.Result{}, err
		}
	}

	// Peers to remove.
	for peerPublicKey := range knownPeerPublicKeys.Difference(remotePeerPublicKeys) {
		slog.Debug("Removing peer", slog.String("publicKey", peerPublicKey))

		if err := t.tun.RemovePeer(peerPublicKey); err != nil {
			slog.Error("Failed to remove peer", slog.String("publicKey", peerPublicKey), slog.Any("error", err))
			continue
		}

		offerName := fmt.Sprintf("%s-%s", t.localTunnelNode.Name, peerPublicKey)
		var peerOffer corev1alpha.TunnelPeerOffer
		if err := t.Get(ctx, client.ObjectKey{Name: offerName}, &peerOffer); err == nil {
			if err := t.Delete(ctx, &peerOffer); err != nil {
				slog.Error("Failed to delete TunnelPeerOffer", slog.String("name", peerOffer.Name), slog.Any("error", err))
			}
		}
	}

	return ctrl.Result{}, nil
}

// upsertTunnelNode creates or updates a TunnelNode object in the API.
// Will wait up to takoverWait if node has been synced before taking over the node.
func (t *tunnelNodeReconciler) upsertTunnelNode(
	ctx context.Context,
	client versioned.Interface,
	takoverWait time.Duration,
) error {
	var updated *corev1alpha.TunnelNode

	existingTunnelNode, err := client.CoreV1alpha().TunnelNodes().Get(ctx, t.localTunnelNode.Name, metav1.GetOptions{})
	if err != nil && !apierrors.IsNotFound(err) {
		return fmt.Errorf("failed to get existing TunnelNode: %w", err)
	} else if apierrors.IsNotFound(err) {
		if updated, err = client.CoreV1alpha().TunnelNodes().Create(ctx, &t.localTunnelNode, metav1.CreateOptions{}); err != nil {
			return fmt.Errorf("failed to create TunnelNode: %w", err)
		}
	} else {
		if existingTunnelNode.Status.LastSynced != nil {
			log.Infof("Detected synced node, waiting for %v before taking over", takoverWait)
			select {
			case <-time.After(takoverWait):
				existingTunnelNode, err = client.CoreV1alpha().TunnelNodes().Get(ctx, t.localTunnelNode.Name, metav1.GetOptions{})
				if err != nil {
					log.Errorf("Failed to re-read TunnelNode: %v", err)
					return err
				}
				if !existingTunnelNode.Status.LastSynced.Equal(existingTunnelNode.Status.LastSynced) {
					log.Infof("TunnelNode was synced while waiting, aborting takeover")
					return fmt.Errorf("tunnel node was synced while waiting - a tunnel peer may have been connected")
				}
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
			existingTunnelNode, err := client.CoreV1alpha().TunnelNodes().Get(ctx, t.localTunnelNode.Name, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to get existing TunnelNode: %w", err)
			}

			t.localTunnelNode.ResourceVersion = existingTunnelNode.ResourceVersion
			t.localTunnelNode.Status.LastSynced = ptr.To(metav1.Now())
			t.localTunnelNode.Status.Epoch = existingTunnelNode.Status.Epoch + 1

			log.Infof("Updating TunnelNode %s with epoch %d", t.localTunnelNode.Name, t.localTunnelNode.Status.Epoch)

			if _, err = client.CoreV1alpha().TunnelNodes().Update(ctx, &t.localTunnelNode, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("failed to update existing TunnelNode: %w", err)
			}
			if updated, err = client.CoreV1alpha().TunnelNodes().UpdateStatus(ctx, &t.localTunnelNode, metav1.UpdateOptions{}); err != nil {
				return fmt.Errorf("failed to update TunnelNode status: %w", err)
			}

			return nil
		}); err != nil {
			return fmt.Errorf("failed to update existing TunnelNode: %w", err)
		}
	}

	t.localTunnelNode = *updated.DeepCopy()

	return nil
}

func (t *tunnelNodeReconciler) runSyncLoop(ctx context.Context, client versioned.Interface) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
			if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
				tn, err := client.CoreV1alpha().TunnelNodes().Get(ctx, t.localTunnelNode.Name, metav1.GetOptions{})
				if err != nil {
					return fmt.Errorf("failed to get existing TunnelNode: %w", err)
				}

				tn.Status.LastSynced = ptr.To(metav1.Now())

				if _, err = client.CoreV1alpha().TunnelNodes().UpdateStatus(ctx, tn, metav1.UpdateOptions{}); err != nil {
					return fmt.Errorf("failed to update existing TunnelNode: %w", err)
				}

				return nil
			}); err != nil {
				slog.Error("Failed to sync TunnelNode status", slog.Any("error", err))
			}
		}
	}
}
