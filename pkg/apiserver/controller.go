package apiserver

import (
	"context"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type Controller interface {
	SetupWithManager(ctx context.Context, mgr ctrl.Manager) error
	Reconcile(ctx context.Context, request reconcile.Request) (ctrl.Result, error)
}

type CreateController func(client.Client) Controller
