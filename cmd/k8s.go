package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/discovery/cached/memory"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
)

var (
	decoder = scheme.Codecs.UniversalDeserializer()
)

func getYAML() ([]byte, error) {
	c, err := defaultAPIClient()
	if err != nil {
		return nil, err
	}

	resp, err := c.SendRequest(http.MethodGet, "/v1/onboarding/k8s.yaml", nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return ioutil.ReadAll(resp.Body)
}

func installController(ctx context.Context, kc *rest.Config, yamlz []byte) error {
	dc, err := discovery.NewDiscoveryClientForConfig(kc)
	if err != nil {
		return err
	}

	dynClient, err := dynamic.NewForConfig(kc)
	if err != nil {
		return err
	}
	mapper := restmapper.NewDeferredDiscoveryRESTMapper(memory.NewMemCacheClient(dc))

	for _, yaml := range strings.Split(string(yamlz), "---") {
		if yaml == "" {
			continue
		}

		obj := &unstructured.Unstructured{}
		_, gvk, err := decoder.Decode([]byte(yaml), nil, obj)
		if err != nil {
			return fmt.Errorf("failed to decode YAML: %w", err)
		}

		mapping, err := mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
		if err != nil {
			return fmt.Errorf("failed to get REST mapping: %w", err)
		}

		var resource dynamic.ResourceInterface
		if mapping.Scope.Name() == meta.RESTScopeNameNamespace { // Namespaced resource.
			resource = dynClient.Resource(mapping.Resource).Namespace(obj.GetNamespace())
		} else { // Cluster-scoped resource.
			resource = dynClient.Resource(mapping.Resource)
		}

		jsonData, err := json.Marshal(obj)
		if err != nil {
			return fmt.Errorf("failed to marshal JSON: %w", err)
		}

		patchOpts := metav1.PatchOptions{
			FieldManager: "apoxy-cli",
		}
		if _, err = resource.Patch(ctx, obj.GetName(), types.ApplyPatchType, jsonData, patchOpts); err != nil {
			return fmt.Errorf("failed to apply patch for %s (%v): %w", obj.GetName(), obj.GroupVersionKind(), err)
		}
	}

	return nil
}

var installK8sCmd = &cobra.Command{
	Use:   "install",
	Short: "Install Apoxy Controller in Kubernetes",
	Long: `Install the Apoxy Controller into the target Kubernetes cluster.

This will create a new namespace and deploy the controller and supporting resources.  The controller
will automatically connect to the Apoxy API and begin managing your in-cluster Apoxy resources.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true

		// 1. If --kubeconfig is set, use that.
		// 2. If KUBECONFIG is set, use that.
		// 3. Otherwise, use the default path.
		kubeconfig, err := cmd.Flags().GetString("kubeconfig")
		if err != nil {
			return err
		}
		if kubeconfig == "" {
			var ok bool
			kubeconfig, ok = os.LookupEnv("KUBECONFIG")
			if !ok {
				kubeconfig = clientcmd.RecommendedHomeFile
			}
		}
		kc, err := clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return fmt.Errorf("failed to build Kubernetes config: %w", err)
		}

		yamlz, err := getYAML()
		if err != nil {
			return fmt.Errorf("failed to get YAML: %w", err)
		}

		if err := installController(cmd.Context(), kc, yamlz); err != nil {
			return fmt.Errorf("failed to install controller: %w", err)
		}

		return nil
	},
}

var k8sCmd = &cobra.Command{
	Use:   "k8s",
	Args:  cobra.NoArgs,
	Short: "Commands that manage Apoxy on Kubernetes",
}

func init() {
	installK8sCmd.Flags().StringP("kubeconfig", "k", "", "Path to the kubeconfig file to use for Kubernetes API access")
	k8sCmd.AddCommand(installK8sCmd)

	rootCmd.AddCommand(k8sCmd)
}
