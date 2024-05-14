package alpha

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/google/uuid"
	"github.com/spf13/cobra"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/apoxy-dev/apoxy-cli/config"
	"github.com/apoxy-dev/apoxy-cli/internal/apiserver"
	apiserverctrl "github.com/apoxy-dev/apoxy-cli/internal/apiserver/controllers"
	"github.com/apoxy-dev/apoxy-cli/internal/backplane/drivers"
	"github.com/apoxy-dev/apoxy-cli/internal/log"
	"github.com/apoxy-dev/apoxy-cli/rest"

	ctrlv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/controllers/v1alpha1"
)

func defaultOrLocalAPIClient(local bool) (*rest.APIClient, error) {
	if local {
		return rest.NewAPIClient("https://localhost:443", "localhost", "", uuid.New())
	}
	return config.DefaultAPIClient()
}

func updateProxyFromFile(ctx context.Context, path string) (*ctrlv1alpha1.Proxy, error) {
	cfg, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	c, err := defaultOrLocalAPIClient(true)
	if err != nil {
		return nil, err
	}
	proxyName, err := proxyName(path)
	if err != nil {
		return nil, err
	}
	proxy := &ctrlv1alpha1.Proxy{
		ObjectMeta: metav1.ObjectMeta{
			Name: proxyName,
		},
		Spec: ctrlv1alpha1.ProxySpec{
			Provider: ctrlv1alpha1.InfraProviderUnmanaged,
			Config:   string(cfg),
		},
	}
	p, err := c.ControllersV1alpha1().Proxies().Create(ctx, proxy, metav1.CreateOptions{})
	if errors.IsAlreadyExists(err) {
		p, err = c.ControllersV1alpha1().Proxies().Get(ctx, proxy.Name, metav1.GetOptions{})
		if err != nil {
			return nil, fmt.Errorf("failed to get proxy: %w", err)
		}
		p.Spec = proxy.Spec
		if _, err = c.ControllersV1alpha1().Proxies().Update(
			ctx,
			p,
			metav1.UpdateOptions{},
		); err != nil {
			return nil, fmt.Errorf("failed to update proxy: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("failed to create proxy: %w", err)
	}
	return p, err
}

func watchAndReloadProxy(ctx context.Context, path string) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close()
	if err := watcher.Add(path); err != nil {
		return err
	}

	if _, err := updateProxyFromFile(ctx, path); err != nil {
		return err
	}
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-watcher.Events:
			if !ok {
				return nil
			}
			if !ev.Has(fsnotify.Write) {
				continue
			}

			// Reload the proxy configuration
			if _, err := updateProxyFromFile(ctx, path); err != nil {
				return err
			}
		case err := <-watcher.Errors:
			return err
		}
	}
	panic("unreachable")
}

func proxyName(path string) (string, error) {
	host, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("failed to get hostname: %w", err)
	}
	basename := filepath.Base(path)
	return fmt.Sprintf(
		"proxy-%s-%s",
		host,
		strings.TrimSuffix(basename, filepath.Ext(basename)),
	), nil
}

var runCmd = &cobra.Command{
	Use:   "run",
	Short: "Run Apoxy server locally",
	Args:  cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		_, err := config.Load()
		if err != nil {
			return err
		}

		path := args[0]
		proxyName, err := proxyName(path)
		if err != nil {
			return err
		}

		startCh := make(chan error)
		go func() {
			mgr, err := apiserver.Start(cmd.Context())
			if err != nil {
				log.Errorf("failed to start API server: %v", err)
				startCh <- err
				return
			}
			startCh <- nil

			if err := apiserverctrl.NewProxyReconciler(
				mgr.GetClient(),
			).SetupWithManager(cmd.Context(), mgr); err != nil {
				log.Errorf("failed to set up Project controller: %v", err)
				return
			}

			if err := mgr.Start(cmd.Context()); err != nil {
				log.Errorf("failed to start manager: %v", err)
			}
		}()
		select {
		case err := <-startCh:
			if err != nil {
				return err
			}
		case <-cmd.Context().Done():
			return nil
		}

		projID := uuid.New()
		d := drivers.GetDriver("local")
		if err := d.Start(cmd.Context(), projID, proxyName); err != nil {
			return err
		}

		if err := watchAndReloadProxy(cmd.Context(), path); err != nil {
			return err
		}

		return nil
	},
}

func init() {
	alphaCmd.AddCommand(runCmd)
}
