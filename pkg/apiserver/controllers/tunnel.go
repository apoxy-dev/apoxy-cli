package controllers

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	controllerlog "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel/token"
)

const (
	expiryDuration = 5 * time.Minute
)

// TunnelNodeReconciler implements a basic garbage collector for dead/orphaned
// TunnelNode objects.
type TunnelNodeReconciler struct {
	client.Client

	jwtPrivateKey         []byte
	jwtPublicKey          []byte
	tokenRefreshThreshold time.Duration

	validator *token.Validator
	issuer    *token.Issuer
}

func NewTunnelNodeReconciler(
	c client.Client,
	jwtPrivateKey []byte,
	jwtPublicKey []byte,
	tokenRefreshThreshold time.Duration,
) *TunnelNodeReconciler {
	return &TunnelNodeReconciler{
		Client:                c,
		jwtPrivateKey:         jwtPrivateKey,
		jwtPublicKey:          jwtPublicKey,
		tokenRefreshThreshold: tokenRefreshThreshold,
	}
}

func (r *TunnelNodeReconciler) isNewTokenNeeded(
	ctx context.Context,
	token, subj string,
) (bool, error) {
	log := controllerlog.FromContext(ctx, "subj", subj)

	if token == "" {
		log.Info("Token is empty")
		return true, nil
	}

	claims, err := r.validator.Validate(token, subj)
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

		tn.Status.Credentials = token

		if err := r.Status().Update(ctx, tn); err != nil {
			return ctrl.Result{}, fmt.Errorf("failed to update status: %w", err)
		}
	}

	return ctrl.Result{}, nil
}

func (r *TunnelNodeReconciler) SetupWithManager(ctx context.Context, mgr ctrl.Manager) error {
	var err error
	r.validator, err = token.NewValidator(r.jwtPublicKey)
	if err != nil {
		return fmt.Errorf("failed to create token validator: %w", err)
	}
	r.issuer, err = token.NewIssuer(r.jwtPrivateKey)
	if err != nil {
		return fmt.Errorf("failed to create token issuer: %w", err)
	}

	return ctrl.NewControllerManagedBy(mgr).
		For(&corev1alpha.TunnelNode{}).
		Complete(r)
}
