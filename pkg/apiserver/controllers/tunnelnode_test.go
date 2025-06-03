package controllers

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	corev1alpha "github.com/apoxy-dev/apoxy/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy/pkg/cryptoutils"
	"github.com/apoxy-dev/apoxy/pkg/tunnel/token"
)

func TestTunnelNodeReconciler(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha.Install(scheme))

	tunnelNode := &corev1alpha.TunnelNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-tunnelnode",
			Namespace: "default",
			UID:       types.UID(uuid.New().String()),
		},
	}

	// Create a fake client with the registered scheme and the TunnelNode object.
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).
		WithObjects(tunnelNode).
		WithStatusSubresource(tunnelNode).
		Build()

	privKey, pubKey, err := cryptoutils.GenerateEllipticKeyPair()
	require.NoError(t, err)

	r := NewTunnelNodeReconciler(
		k8sClient,
		"localhost",
		9444,
		privKey,
		pubKey,
		time.Minute,
	)

	r.validator, err = token.NewInMemoryValidator(r.jwtPublicKeyPEM)
	require.NoError(t, err)
	r.issuer, err = token.NewIssuer(r.jwtPrivateKeyPEM)
	require.NoError(t, err)

	// Call the reconcile method.
	_, err = r.Reconcile(context.TODO(), reconcile.Request{
		NamespacedName: types.NamespacedName{
			Name:      "test-tunnelnode",
			Namespace: "default",
		},
	})
	require.NoError(t, err)
}
