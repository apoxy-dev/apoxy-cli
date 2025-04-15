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

	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy-cli/pkg/tunnel/token"
	"github.com/apoxy-dev/apoxy-cli/pkg/utils"
)

func TestTunnelNodeReconciler(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, corev1alpha.Install(scheme))

	// Create a fake client with the registered scheme.
	k8sClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	privKey, pubKey, err := utils.GenerateEllipticKeyPair()
	require.NoError(t, err)

	r := NewTunnelNodeReconciler(
		k8sClient,
		"localhost",
		9444,
		privKey,
		pubKey,
		time.Minute,
	)

	r.validator, err = token.NewInMemoryValidator(r.jwtPublicKey)
	require.NoError(t, err)
	r.issuer, err = token.NewIssuer(r.jwtPrivateKey)
	require.NoError(t, err)

	tunnelNode := &corev1alpha.TunnelNode{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-tunnelnode",
			Namespace: "default",
			UID:       types.UID(uuid.New().String()),
		},
	}

	// Add the TunnelNode to the fake client.
	err = k8sClient.Create(context.TODO(), tunnelNode)
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
