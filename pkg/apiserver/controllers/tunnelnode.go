package controllers

import (
	"context"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/MicahParks/jwkset"
	"github.com/google/uuid"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerlog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel/token"
)

// TunnelNodeReconciler implements a basic garbage collector for dead/orphaned
// TunnelNode objects.
type TunnelNodeReconciler struct {
	client.Client

	jwksHost              string
	jwksPort              int
	jwtPrivateKey         []byte
	jwtPublicKey          []byte
	tokenRefreshThreshold time.Duration

	validator *token.InMemoryValidator
	issuer    *token.Issuer
	jwkSet    *jwkset.MemoryJWKSet
}

func NewTunnelNodeReconciler(
	c client.Client,
	jwksHost string,
	jwksPort int,
	jwtPrivateKey []byte,
	jwtPublicKey []byte,
	tokenRefreshThreshold time.Duration,
) *TunnelNodeReconciler {
	return &TunnelNodeReconciler{
		Client:                c,
		jwksHost:              jwksHost,
		jwksPort:              jwksPort,
		jwtPrivateKey:         jwtPrivateKey,
		jwtPublicKey:          jwtPublicKey,
		tokenRefreshThreshold: tokenRefreshThreshold,
		jwkSet:                jwkset.NewMemoryStorage(),
	}
}

func (r *TunnelNodeReconciler) isNewTokenNeeded(
	ctx context.Context,
	credentials *corev1alpha.TunnelNodeCredentials,
	subj string,
) (bool, error) {
	log := controllerlog.FromContext(ctx, "subj", subj)

	if credentials == nil {
		log.Info("Credentials are nil")
		return true, nil
	}

	if credentials.Token == "" {
		log.Info("Token is empty")
		return true, nil
	}

	claims, err := r.validator.Validate(credentials.Token, subj)
	if err != nil { // Not supposed to happen so log the issue
		log.Error(err, "Token validation failed")
		return true, nil
	}

	exp, err := claims.GetExpirationTime()
	if err != nil {
		log.Error(err, "Failed to get expiration time")
		return true, nil
	}

	if exp.Before(time.Now().Add(r.tokenRefreshThreshold)) {
		log.Info("Token is about to expire", "exp", exp, "threshold", r.tokenRefreshThreshold)
		return true, nil
	}

	return false, nil
}

func (r *TunnelNodeReconciler) Reconcile(ctx context.Context, req reconcile.Request) (ctrl.Result, error) {
	log := controllerlog.FromContext(ctx, "name", req.Name)

	tn := &corev1alpha.TunnelNode{}
	if err := r.Get(ctx, req.NamespacedName, tn); err != nil {
		if client.IgnoreNotFound(err) != nil {
			return ctrl.Result{}, err
		}
		log.V(1).Info("TunnelNode not found")
		return ctrl.Result{}, nil // Not found
	}

	log.Info("Reconciling TunnelNode")

	if !tn.ObjectMeta.DeletionTimestamp.IsZero() {
		log.Info("TunnelNode is being deleted")
		// TODO(dsky): Wait for all clients to disconnect before deleting (with grace period).
		return ctrl.Result{}, nil // Deleted
	}

	if ok, err := r.isNewTokenNeeded(
		controllerlog.IntoContext(ctx, log),
		tn.Status.Credentials,
		string(tn.ObjectMeta.UID),
	); err != nil {
		return ctrl.Result{}, fmt.Errorf("failed to check if new token is needed: %w", err)
	} else if ok {
		subj, err := uuid.Parse(string(tn.ObjectMeta.UID))
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to parse UID as UUID: %w", err)
		}

		token, claims, err := r.issuer.IssueToken(subj, 2*r.tokenRefreshThreshold)
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to issue token: %w", err)
		}
		exp, err := claims.GetExpirationTime()
		if err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to get expiration from token claims: %w", err)
		}

		log.Info("Issued new token", "subj", subj, "exp", exp)

		tn.Status.Credentials = &corev1alpha.TunnelNodeCredentials{
			Token: token,
		}

		if err := r.Status().Update(ctx, tn); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update status: %w", err)
		}
	}

	return ctrl.Result{}, nil
}

// JWKSHandler returns an http.HandlerFunc that serves the JWKS at the
// standard JWKS path.
func (r *TunnelNodeReconciler) JWKSHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		resp, err := r.jwkSet.JSONPublic(req.Context())
		if err != nil {
			slog.Error("Failed to get JWK Set JSON.", slog.Any("error", err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(resp)
	}
}

func (r *TunnelNodeReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	var err error
	r.validator, err = token.NewInMemoryValidator(r.jwtPublicKey)
	if err != nil {
		return fmt.Errorf("failed to create token validator: %w", err)
	}
	r.issuer, err = token.NewIssuer(r.jwtPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create token issuer: %w", err)
	}

	// TODO(dsky): Implement key rotation.
	pubKey, _ := pem.Decode(r.jwtPublicKey)
	if pubKey == nil {
		return fmt.Errorf("failed to decode private key")
	}
	key, err := jwkset.LoadX509KeyInfer(pubKey)
	if err != nil {
		return fmt.Errorf("failed to load X509 key: %w", err)
	}
	metadata := jwkset.JWKMetadataOptions{
		KID: r.issuer.KeyID(),
	}
	jwk, err := jwkset.NewJWKFromKey(key, jwkset.JWKOptions{
		Metadata: metadata,
		Marshal: jwkset.JWKMarshalOptions{
			Private: false,
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create JWK: %w", err)
	}
	if err := r.jwkSet.KeyWrite(ctx, jwk); err != nil {
		return fmt.Errorf("failed to write JWK: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha.TunnelNode{}).
		Complete(r)
}

// ServeJWKS starts an HTTP server to serve JWK sets
func (r *TunnelNodeReconciler) ServeJWKS(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc(token.JWKSURI, r.JWKSHandler())

	server := &http.Server{
		Addr:    fmt.Sprintf("%s:%d", r.jwksHost, r.jwksPort),
		Handler: mux,
	}

	slog.Info("Starting JWKS HTTP server", slog.String("addr", server.Addr))

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if err := server.Shutdown(shutdownCtx); err != nil {
			slog.Error("Failed to shutdown JWKS server", slog.Any("error", err))
		}
	}()

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("JWKS server failed: %w", err)
	}

	return nil
}
