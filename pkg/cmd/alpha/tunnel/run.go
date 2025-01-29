package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"k8s.io/utils/set"

	"github.com/pion/ice/v4"
	icelogging "github.com/pion/logging"
	"github.com/pion/stun/v3"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"

	"github.com/apoxy-dev/apoxy-cli/client/informers"
	"github.com/apoxy-dev/apoxy-cli/client/versioned"
	"github.com/apoxy-dev/apoxy-cli/config"
	"github.com/apoxy-dev/apoxy-cli/pkg/log"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel"
	"github.com/apoxy-dev/apoxy-cli/pkg/wireguard"

	corev1alphaclient "github.com/apoxy-dev/apoxy-cli/client/listers/core/v1alpha"

	configv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/config/v1alpha1"
	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
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

		client, err := config.DefaultAPIClient()
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

				if err := client.CoreV1alpha().TunnelNodes().Delete(ctx, tn.Name, metav1.DeleteOptions{}); err != nil {
					log.Errorf("Failed to delete TunnelNode: %v", err)
				}
			}()
		} else if tunnelNodeName != "" {
			tn, err = client.CoreV1alpha().TunnelNodes().Get(ctx, tunnelNodeName, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("unable to get TunnelNode: %w", err)
			}
		} else {
			return fmt.Errorf("either --file or stdin must be specified")
		}

		iceConf := &ice.AgentConfig{
			Urls: []*stun.URI{
				{
					Scheme: stun.SchemeTypeSTUN,
					Host:   "stun.l.google.com",
					Port:   19302,
				},
				//{
				//	Scheme:   stun.SchemeTypeTURN,
				//	Host:     "turn.cloudflare.com",
				//	Port:     3478,
				//	Username: "g06a58ffa5a7334919604e8b014e9b94369c74d38259612c7ebe9acd6a7953a6",
				//	Password: "c1279ef392a52b63667758cb544c6f1d02f1d64c752712a973a16e51069c8d30",
				//	Proto:    stun.ProtoTypeUDP,
				//},
				//{
				//	Scheme:   stun.SchemeTypeTURN,
				//	Host:     "turn.cloudflare.com",
				//	Port:     3478,
				//	Username: "g06a58ffa5a7334919604e8b014e9b94369c74d38259612c7ebe9acd6a7953a6",
				//	Password: "c1279ef392a52b63667758cb544c6f1d02f1d64c752712a973a16e51069c8d30",
				//	Proto:    stun.ProtoTypeTCP,
				//},
			},
			NetworkTypes:  []ice.NetworkType{ice.NetworkTypeUDP4},
			CheckInterval: ptr.To(20 * time.Millisecond),
			CandidateTypes: []ice.CandidateType{
				ice.CandidateTypeHost,
				ice.CandidateTypeServerReflexive,
				ice.CandidateTypeRelay,
			},
			LoggerFactory: &icelogging.DefaultLoggerFactory{
				Writer: log.NewDefaultLogWriter(log.InfoLevel),
			},
		}

		tun := &tunnelNode{
			TunnelNode: tn,
			cfg:        cfg,
			bind:       wireguard.NewIceBind(ctx, iceConf),
			a3y:        client,
		}
		return tun.run(ctx)
	},
}

type tunnelNode struct {
	*corev1alpha.TunnelNode
	a3y  versioned.Interface
	bind *wireguard.IceBind
	cfg  *configv1alpha1.Config
}

func (t *tunnelNode) run(ctx context.Context) error {
	var err error

	var tun tunnel.Tunnel
	tunAddr := tunnel.NewApoxy4To6Prefix(t.cfg.CurrentProject, t.TunnelNode.Name)
	if t.cfg.Tunnel != nil && t.cfg.Tunnel.Mode == configv1alpha1.TunnelModeUserspace {
		socksPort := uint16(1080)
		if t.cfg.Tunnel.SocksPort != nil {
			socksPort = uint16(*t.cfg.Tunnel.SocksPort)
		}

		tun, err = tunnel.CreateUserspaceTunnel(ctx, tunAddr.Addr(), t.bind, socksPort, t.cfg.Verbose)
	} else {
		tun, err = tunnel.CreateKernelTunnel(ctx)
	}
	if err != nil {
		return fmt.Errorf("unable to create tunnel: %w", err)
	}
	defer tun.Close()

	slog.Debug("Running TunnelNode controller",
		slog.String("name", t.TunnelNode.Name), slog.String("publicKey", tun.PublicKey()),
		slog.String("internalAddress", tun.InternalAddress().String()))

	client, err := config.DefaultAPIClient()
	if err != nil {
		return fmt.Errorf("unable to create API client: %w", err)
	}

	factory := informers.NewSharedInformerFactoryWithOptions(
		client,
		resyncPeriod,
	)

	tunnelNodeInformer := factory.Core().V1alpha().TunnelNodes().Informer()
	tunnelNodeLister := factory.Core().V1alpha().TunnelNodes().Lister()

	doneCh := make(chan struct{})
	tunnelNodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			updatedTunnelNode, ok := obj.(*corev1alpha.TunnelNode)
			if !ok {
				return
			}

			t.handleTunnelNodeUpdate(tunnelNodeLister, t.TunnelNode.Name, tun, updatedTunnelNode)
		},
		UpdateFunc: func(_, newObj any) {
			updatedTunnelNode, ok := newObj.(*corev1alpha.TunnelNode)
			if !ok {
				return
			}

			t.handleTunnelNodeUpdate(tunnelNodeLister, t.TunnelNode.Name, tun, updatedTunnelNode)
		},
		DeleteFunc: func(obj any) {
			deletedTunnelNode, ok := obj.(*corev1alpha.TunnelNode)
			if !ok {
				return
			}

			if deletedTunnelNode.Name != t.TunnelNode.Name {
				// Nothing for us to do.
				return
			}

			doneCh <- struct{}{}
		},
	})

	factory.Start(ctx.Done())
	synced := factory.WaitForCacheSync(ctx.Done())
	for v, s := range synced {
		if !s {
			return fmt.Errorf("informer %s failed to sync", v)
		}
	}

	// Set the initial status of the TunnelNode object.
	t.TunnelNode.Status.Phase = corev1alpha.NodePhaseReady
	t.TunnelNode.Status.PublicKey = tun.PublicKey()
	t.TunnelNode.Status.ExternalAddress = tun.ExternalAddress().String()
	t.TunnelNode.Status.InternalAddress = tun.InternalAddress().String()

	// Create/update the TunnelNode object in the API.
	slog.Debug("Creating/updating TunnelNode", slog.String("name", t.TunnelNode.Name))

	if err := upsertTunnelNode(ctx, client, t.TunnelNode); err != nil {
		return err
	}

	// Wait for the TunnelNode object to be deleted, or for the command to be cancelled.
	select {
	case <-doneCh:
	case <-ctx.Done():
	}

	return nil
}

// handleTunnelNodeUpdate is called every time a TunnelNode object is added or updated.
func (t *tunnelNode) handleTunnelNodeUpdate(
	tunnelNodeLister corev1alphaclient.TunnelNodeLister,
	tunnelNodeName string,
	tun tunnel.Tunnel,
	updatedTunnelNode *corev1alpha.TunnelNode,
) {
	var tunnelNode *corev1alpha.TunnelNode
	if updatedTunnelNode.Name == tunnelNodeName {
		// The updated object is the one we are managing.
		tunnelNode = updatedTunnelNode
	} else {
		// A different object was updated. We need to check if it references the object we are managing.
		var err error
		tunnelNode, err = tunnelNodeLister.Get(tunnelNodeName)
		if err != nil {
			if !errors.IsNotFound(err) {
				slog.Warn("Failed to get TunnelNode",
					slog.String("name", tunnelNodeName), slog.Any("error", err))
			}
			return
		}

		// Do we have a reference to the object?
		var foundRef bool
		for _, peer := range tunnelNode.Spec.Peers {
			if peer.TunnelNodeRef != nil {
				if peer.TunnelNodeRef.Name == updatedTunnelNode.Name {
					foundRef = true
					break
				}
			} else if peer.LabelSelector != nil {
				selector, err := metav1.LabelSelectorAsSelector(peer.LabelSelector)
				if err != nil {
					slog.Warn("Invalid label selector", slog.Any("error", err))
					continue
				}

				peerTunnelNodesList, err := tunnelNodeLister.List(selector)
				if err != nil {
					slog.Warn("Failed to list TunnelNodes", slog.Any("error", err))
					continue
				}

				for _, peerTunnelNode := range peerTunnelNodesList {
					if peerTunnelNode.Name == updatedTunnelNode.Name {
						foundRef = true
						break
					}
				}
			}
		}

		if !foundRef {
			// The updated object is not referenced by the object we are managing.
			return
		}
	}

	t.syncTunnelNode(tunnelNodeLister, tunnelNode, tun)
}

// syncTunnelNode reconciles the state of our TunnelNode object with the state of the tunnel.
func (t *tunnelNode) syncTunnelNode(
	tunnelNodeLister corev1alphaclient.TunnelNodeLister,
	tunnelNode *corev1alpha.TunnelNode,
	tun tunnel.Tunnel,
) {
	peerPublicKeys := set.New[string]()
	peerTunnelNodes := map[string]*corev1alpha.TunnelNode{}

	for _, peer := range tunnelNode.Spec.Peers {
		if peer.TunnelNodeRef != nil {
			peerTunnelNode, err := tunnelNodeLister.Get(peer.TunnelNodeRef.Name)
			if err != nil {
				if !errors.IsNotFound(err) {
					slog.Warn("Failed to get peer", slog.String("name", peer.TunnelNodeRef.Name), slog.Any("error", err))
				}
				continue
			}

			if peerTunnelNode.Status.PublicKey != "" {
				peerPublicKeys.Insert(peerTunnelNode.Status.PublicKey)
				peerTunnelNodes[peerTunnelNode.Status.PublicKey] = peerTunnelNode
			}
		} else if peer.LabelSelector != nil {
			selector, err := metav1.LabelSelectorAsSelector(peer.LabelSelector)
			if err != nil {
				slog.Warn("Invalid label selector", slog.Any("error", err))
				continue
			}

			peerTunnelNodeList, err := tunnelNodeLister.List(selector)
			if err != nil {
				slog.Warn("Failed to list TunnelNodes", slog.Any("error", err))
				continue
			}

			for _, peerTunnelNode := range peerTunnelNodeList {
				if peerTunnelNode.Status.PublicKey != "" {
					peerPublicKeys.Insert(peerTunnelNode.Status.PublicKey)
					peerTunnelNodes[peerTunnelNode.Status.PublicKey] = peerTunnelNode
				}
			}
		}
	}

	knownPeers, err := tun.Peers()
	if err != nil {
		slog.Error("Failed to get known peers", slog.String("name", tunnelNode.Name), slog.Any("error", err))
		return
	}

	log.Debugf("Known peers: %v", knownPeers)

	knownPeerPublicKeys := set.New[string]()
	for _, peerConf := range knownPeers {
		knownPeerPublicKeys.Insert(*peerConf.PublicKey)
	}

	// Check for peers with no longer valid configurations.
	for _, peerConf := range knownPeers {
		peerTunnelNode, ok := peerTunnelNodes[*peerConf.PublicKey]
		if !ok {
			continue
		}

		// Check if the peer configuration has changed.
		var peerConfChanged bool
		if *peerConf.PublicKey != peerTunnelNode.Status.PublicKey {
			peerConfChanged = true
		}
		if (peerConf.Endpoint == nil && peerTunnelNode.Status.ExternalAddress != "") ||
			(peerConf.Endpoint != nil && *peerConf.Endpoint != peerTunnelNode.Status.ExternalAddress) {
			peerConfChanged = true
		}
		if (len(peerConf.AllowedIPs) == 0 && peerTunnelNode.Status.InternalAddress != "") ||
			(len(peerConf.AllowedIPs) > 0 && peerConf.AllowedIPs[0] != peerTunnelNode.Status.InternalAddress) {
			peerConfChanged = true
		}

		if peerConfChanged {
			slog.Debug("Peer configuration changed", slog.String("name", peerTunnelNode.Name))

			if err := tun.RemovePeer(*peerConf.PublicKey); err != nil {
				slog.Error("Failed to remove peer", slog.String("name", peerTunnelNode.Name), slog.Any("error", err))
			}

			// Will be re-added below with the new configuration.
			peerPublicKeys.Delete(*peerConf.PublicKey)
		}
	}

	// New peers to add.
	for peerPublicKey := range peerPublicKeys.Difference(knownPeerPublicKeys) {
		peerTunnelNode := peerTunnelNodes[peerPublicKey]

		remoteUfrag, err := t.offerExchange(context.Background(), tunnelNode, peerTunnelNode)
		if err != nil {
			slog.Error("Failed to exchange ICE offer", slog.String("name", peerTunnelNode.Name), slog.Any("error", err))
			continue
		}

		peerConf := &wireguard.PeerConfig{
			PublicKey:                      ptr.To(peerTunnelNode.Status.PublicKey),
			AllowedIPs:                     []string{peerTunnelNode.Status.InternalAddress},
			Endpoint:                       ptr.To(remoteUfrag),
			PersistentKeepaliveIntervalSec: ptr.To(uint16(5)),
		}

		slog.Debug("Adding peer",
			slog.String("name", peerTunnelNode.Name),
			slog.String("publicKey", peerPublicKey),
			slog.String("endpoint", remoteUfrag))

		if err := tun.AddPeer(peerConf); err != nil {
			slog.Error("Failed to add peer", slog.String("name", peerTunnelNode.Name), slog.Any("error", err))
		}
	}

	// Peers to remove.
	for peerPublicKey := range knownPeerPublicKeys.Difference(peerPublicKeys) {
		slog.Debug("Removing peer", slog.String("publicKey", peerPublicKey))

		if err := tun.RemovePeer(peerPublicKey); err != nil {
			slog.Error("Failed to remove peer", slog.String("publicKey", peerPublicKey), slog.Any("error", err))
		}

		// TODO(dsky): Remove peer from bind.
	}
}

func (t *tunnelNode) offerExchange(ctx context.Context, local, remote *corev1alpha.TunnelNode) (string, error) {
	// Whichever TunnelNode has larger uuid sum is the controlling node
	isOfferCreator := local.UID > remote.UID
	log.Debugf("Local peer UUID: %s, Remote peer UUID: %s, Offer creator: %t", local.UID, remote.UID, isOfferCreator)
	offerName := fmt.Sprintf("%s-%s", local.Name, remote.Name)
	if !isOfferCreator {
		offerName = fmt.Sprintf("%s-%s", remote.Name, local.Name)
	}

	peer, err := t.bind.NewPeer(ctx, isOfferCreator)
	if err != nil {
		return "", fmt.Errorf("failed to create ICE peer: %w", err)
	}
	if err := peer.Init(ctx); err != nil {
		return "", fmt.Errorf("failed to initialize ICE peer: %w", err)
	}
	time.Sleep(5 * time.Second) // Wait for ICE candidates
	ufrag, pwd := peer.LocalUserCredentials()
	candidates, err := peer.LocalCandidates()
	if err != nil {
		return "", fmt.Errorf("failed to get local candidates: %w", err)
	}

	if isOfferCreator { // If we are controlling node, create offer.
		log.Debugf("Exchanging ICE offer with %s as offer creator (offerName: %s)", remote.Name, offerName)
		if _, err := t.a3y.CoreV1alpha().TunnelPeerOffers().Create(ctx, &corev1alpha.TunnelPeerOffer{
			ObjectMeta: metav1.ObjectMeta{
				Name: offerName,
			},
			Spec: corev1alpha.TunnelPeerOfferSpec{
				ICEOffer: corev1alpha.ICEOffer{
					Ufrag:      ufrag,
					Password:   pwd,
					Candidates: candidates,
				},
			},
		}, metav1.CreateOptions{}); err != nil {
			if errors.IsAlreadyExists(err) {
				// Update existing offer
				existingOffer, err := t.a3y.CoreV1alpha().TunnelPeerOffers().Get(ctx, offerName, metav1.GetOptions{})
				if err != nil {
					return "", fmt.Errorf("failed to get existing TunnelPeerOffer: %w", err)
				}
				existingOffer.Spec.ICEOffer = corev1alpha.ICEOffer{
					Ufrag:      ufrag,
					Password:   pwd,
					Candidates: candidates,
				}
				existingOffer.Status.PeerOffer = nil
				if _, err = t.a3y.CoreV1alpha().TunnelPeerOffers().Update(ctx, existingOffer, metav1.UpdateOptions{}); err != nil {
					return "", fmt.Errorf("failed to update TunnelPeerOffer: %w", err)
				}
			} else {
				return "", fmt.Errorf("failed to create TunnelPeerOffer: %w", err)
			}
		}
	} else {
		log.Debugf("Exchanging ICE offer with %s as offer receiver", local.Name)
	}

	w, err := t.a3y.CoreV1alpha().TunnelPeerOffers().Watch(ctx, metav1.ListOptions{
		FieldSelector: fmt.Sprintf("metadata.name=%s", offerName),
	})
	if err != nil {
		return "", fmt.Errorf("failed to watch TunnelPeerOffer: %w", err)
	}
	defer w.Stop()

	// Wait for the offer to be created.
	for {
		select {
		case <-ctx.Done():
			return "", fmt.Errorf("timed out waiting on offer: %w", ctx.Err())
		case e, ok := <-w.ResultChan():
			if !ok {
				return "", fmt.Errorf("watch channel closed")
			}

			log.Debugf("Received event %s", e.Type)

			var remoteOffer *corev1alpha.ICEOffer
			if isOfferCreator { // If we are controlling node, get peer offer from status
				remote := e.Object.(*corev1alpha.TunnelPeerOffer)
				if remote.Status.PeerOffer == nil {
					log.Debugf("Offer not yet created, waiting...")
					continue // Offer not yet created
				}
				remoteOffer = remote.Status.PeerOffer
			} else {
				remoteOffer = &e.Object.(*corev1alpha.TunnelPeerOffer).Spec.ICEOffer

				// If we are not controlling node, update the offer status with the local peer's offer.
				log.Debugf("Updating offer status with local peer's offer")
				if err := retry.RetryOnConflict(retry.DefaultBackoff, func() error {
					tn, err := t.a3y.CoreV1alpha().TunnelPeerOffers().Get(ctx, offerName, metav1.GetOptions{})
					if err != nil {
						return fmt.Errorf("failed to get TunnelPeerOffer: %w", err)
					}
					tn.Status.PeerOffer = &corev1alpha.ICEOffer{
						Ufrag:      ufrag,
						Password:   pwd,
						Candidates: candidates,
					}
					if _, err = t.a3y.CoreV1alpha().TunnelPeerOffers().UpdateStatus(ctx, tn, metav1.UpdateOptions{}); err != nil {
						return fmt.Errorf("failed to update TunnelPeerOffer status: %w", err)
					}
					return nil
				}); err != nil {
					return "", fmt.Errorf("failed to update TunnelPeerOffer status: %w", err)
				}
			}

			log.Debugf("Received remote ICE offer: %v", remoteOffer)

			if err := peer.Connect(ctx, remoteOffer.Ufrag, remoteOffer.Password, remoteOffer.Candidates); err != nil {
				return "", fmt.Errorf("failed to dial peer: %w", err)
			}

			return remoteOffer.Ufrag, nil
		}
	}
}

// upsertTunnelNode creates or updates a TunnelNode object in the API.
func upsertTunnelNode(ctx context.Context, client versioned.Interface, tunnelNode *corev1alpha.TunnelNode) error {
	return retry.RetryOnConflict(retry.DefaultBackoff, func() error {
		existingTunnelNode, err := client.CoreV1alpha().TunnelNodes().Get(ctx, tunnelNode.Name, metav1.GetOptions{})
		if err == nil {
			// Update the existing TunnelNode.
			tunnelNode.ResourceVersion = existingTunnelNode.ResourceVersion

			_, err = client.CoreV1alpha().TunnelNodes().Update(ctx, tunnelNode, metav1.UpdateOptions{})
			if err != nil {
				return fmt.Errorf("failed to update existing TunnelNode: %w", err)
			}
		} else {
			// Create a new TunnelNode.
			if _, err := client.CoreV1alpha().TunnelNodes().Create(ctx, tunnelNode, metav1.CreateOptions{}); err != nil {
				return fmt.Errorf("failed to create TunnelNode: %w", err)
			}

			existingTunnelNode, err := client.CoreV1alpha().TunnelNodes().Get(ctx, tunnelNode.Name, metav1.GetOptions{})
			if err != nil {
				return fmt.Errorf("failed to get newly created TunnelNode: %w", err)
			}

			tunnelNode.ResourceVersion = existingTunnelNode.ResourceVersion
		}

		_, err = client.CoreV1alpha().TunnelNodes().UpdateStatus(ctx, tunnelNode, metav1.UpdateOptions{})
		if err != nil {
			return fmt.Errorf("failed to update TunnelNode status: %w", err)
		}

		return nil
	})
}
