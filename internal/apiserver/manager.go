package apiserver

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	gw "github.com/apoxy-dev/apoxy-cli/internal/gateway"
	tclient "go.temporal.io/sdk/client"
	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	apiserver "k8s.io/apiserver/pkg/server"
	apiserveropts "k8s.io/apiserver/pkg/server/options"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	certutil "k8s.io/client-go/util/cert"
	"k8s.io/klog/v2"
	netutils "k8s.io/utils/net"
	"sigs.k8s.io/apiserver-runtime/pkg/builder"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/apoxy-dev/apoxy-cli/config"
	"github.com/apoxy-dev/apoxy-cli/internal/apiserver/auth"
	"github.com/apoxy-dev/apoxy-cli/internal/apiserver/controllers"
	"github.com/apoxy-dev/apoxy-cli/internal/apiserver/extensions"
	"github.com/apoxy-dev/apoxy-cli/internal/apiserver/gateway"
	"github.com/apoxy-dev/apoxy-cli/internal/log"
	"github.com/sirupsen/logrus"

	ctrlv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/controllers/v1alpha1"
	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	extensionsv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/extensions/v1alpha1"
	gatewayv1 "github.com/apoxy-dev/apoxy-cli/api/gateway/v1"
	apoxyopenapi "github.com/apoxy-dev/apoxy-cli/api/generated"
	policyv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/policy/v1alpha1"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(corev1alpha.Install(scheme))
	utilruntime.Must(ctrlv1alpha1.Install(scheme))
	utilruntime.Must(policyv1alpha1.Install(scheme))
	utilruntime.Must(extensionsv1alpha1.Install(scheme))
	utilruntime.Must(gatewayv1.Install(scheme))

	// Disable feature gates here. Example:
	// feature.DefaultMutableFeatureGate.Set(string(features.APIPriorityAndFairness) + "=false")
}

func waitForReadyz(url string, timeout time.Duration) error {
	t := time.NewTimer(timeout)
	retryTimeout := 200 * time.Millisecond
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
		Timeout: retryTimeout,
	}

	for {
		resp, err := client.Get(url + "/readyz")
		if err == nil && resp.StatusCode == http.StatusOK {
			return nil
		}

		log.Debugf("failed readyz request: %v", err)

		select {
		case <-t.C:
			return errors.New("timed out waiting for readyz")
		case <-time.After(retryTimeout):
		}
	}
}

type certSource struct {
	cert, key []byte
}

func newSelfSignedCert() (*certSource, error) {
	cert, key, err := certutil.GenerateSelfSignedCertKeyWithFixtures(
		"localhost",
		nil, // IP addresses
		nil, // alternate names
		"",
	)
	if err != nil {
		return nil, fmt.Errorf("failed to generate self-signed certificate: %w", err)
	}
	return &certSource{cert: cert, key: key}, nil
}

func (c *certSource) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return &tls.Certificate{
		Certificate: [][]byte{c.cert},
		PrivateKey:  c.key,
	}, nil
}

// Option is an API server option.
type Option func(*options)

type options struct {
	clientConfig          *rest.Config
	enableSimpleAuth      bool
	enableInClusterAuth   bool
	sqlitePath            string
	certPairName, certDir string
}

// WithClientConfig sets the client configuration.
func WithClientConfig(cfg *rest.Config) Option {
	return func(o *options) {
		o.clientConfig = cfg
	}
}

// WithSimpleAuth enables authentication.
func WithSimpleAuth() Option {
	return func(o *options) {
		o.enableSimpleAuth = true
	}
}

// WithInClusterAuth enables in-cluster authentication.
func WithInClusterAuth() Option {
	return func(o *options) {
		o.enableInClusterAuth = true
	}
}

// WithSQLitePath sets the path to the SQLite database.
// If empty, in-memory database will be used.
func WithSQLitePath(path string) Option {
	return func(o *options) {
		o.sqlitePath = path
	}
}

// WithCerts sets the certificate pair name and directory.
func WithCerts(certPairName, certDir string) Option {
	return func(o *options) {
		o.certPairName = certPairName
		o.certDir = certDir
	}
}

// WithGateway

// defaultOptions returns default options.
func defaultOptions() *options {
	return &options{
		clientConfig:        NewClientConfig(),
		enableSimpleAuth:    false,
		enableInClusterAuth: false,
		sqlitePath:          config.ApoxyDir() + "/apoxy.db",
		certPairName:        "",
		certDir:             "",
	}
}

// Manager manages APIServer instance as well as built-in controllers.
type Manager struct {
	ReadyCh chan struct{}

	manager manager.Manager
}

// New creates a new API server manager.
func New() *Manager {
	return &Manager{
		ReadyCh: make(chan struct{}),
	}
}

// Start starts the API server manager with the given options and blocks forever or
// until the context is canceled (whichever comes first).
// It returns an error if the manager fails to start.
// The manager is ready to serve when the ReadyCh channel is closed.
func (m *Manager) Start(
	ctx context.Context,
	gwSrv *gw.Server,
	tc tclient.Client,
	opts ...Option,
) error {
	var err error
	m.manager, err = start(ctx, opts...)
	if err != nil {
		close(m.ReadyCh)
		return err
	}
	close(m.ReadyCh)

	if err := controllers.NewProxyReconciler(
		m.manager.GetClient(),
	).SetupWithManager(ctx, m.manager); err != nil {
		return fmt.Errorf("failed to set up Project controller: %v", err)
	}
	if err := (&ctrlv1alpha1.Proxy{}).SetupWebhookWithManager(m.manager); err != nil {
		return fmt.Errorf("failed to set up Proxy webhook: %v", err)
	}

	if err := gateway.NewGatewayReconciler(
		m.manager.GetClient(),
		gwSrv.Resources,
	).SetupWithManager(ctx, m.manager); err != nil {
		return fmt.Errorf("failed to set up Project controller: %v", err)
	}

	if err := extensions.NewEdgeFuncReconciler(
		m.manager.GetClient(),
		tc,
	).SetupWithManager(ctx, m.manager); err != nil {
		return fmt.Errorf("failed to set up Project controller: %v", err)
	}
	if err := (&extensionsv1alpha1.EdgeFunction{}).SetupWebhookWithManager(m.manager); err != nil {
		return fmt.Errorf("failed to set up EdgeFunction webhook: %v", err)
	}

	return m.manager.Start(ctx)
}

// start starts the API server and returns the manager (that can be used to start the controller
// manager). The manager must be started by the caller.
func start(
	ctx context.Context,
	opts ...Option,
) (manager.Manager, error) {
	dOpts := defaultOptions()
	for _, o := range opts {
		o(dOpts)
	}
	// Reset flags. APIServer cmd expects its own flagset.
	flag.CommandLine = flag.NewFlagSet("apiserver", flag.ExitOnError)
	os.Args = append(
		[]string{
			os.Args[0],
			// Disable API priority and fairness (flow control) which doesn't work anyway.
			"--enable-priority-and-fairness=false",
		},
		flag.Args()...) // Keep non-flag arguments.

	var simpleAuth authenticator.Request
	if dOpts.enableSimpleAuth {
		var err error
		simpleAuth, err = auth.NewHeaderAuthenticator()
		if err != nil {
			log.Fatalf("Failed to create authenticator: %v", err)
		}
	}

	l := log.New(config.Verbose)
	ctrl.SetLogger(l)
	klog.SetLogger(l)
	// Disables useless kine logging.
	logrus.SetOutput(io.Discard)

	readyCh := make(chan error)
	go func() {
		if dOpts.sqlitePath != "" && !strings.Contains(dOpts.sqlitePath, ":memory:") {
			if _, err := os.Stat(dOpts.sqlitePath); os.IsNotExist(err) {
				if err := os.MkdirAll(filepath.Dir(dOpts.sqlitePath), 0755); err != nil {
					log.Fatalf("Failed to create database directory: %v", err)
				}
				if _, err := os.Create(dOpts.sqlitePath); err != nil {
					log.Fatalf("Failed to create database file: %v", err)
				}
			}
		}
		kineStore, err := NewKineStorage(ctx, "sqlite://"+dOpts.sqlitePath)
		if err != nil {
			readyCh <- fmt.Errorf("failed to create kine storage: %w", err)
			return
		}

		if err := builder.APIServer.
			// OpenAPI types needs to be generated by running generator
			// from (https://github.com/kubernetes/code-generator/tree/master/cmd/openapi-gen):
			// openapi-gen \
			//    --input-dirs k8s.io/apimachinery/pkg/apis/meta/v1,\
			// k8s.io/apimachinery/pkg/api/resource,\
			// k8s.io/apimachinery/pkg/runtime,\
			// k8s.io/apimachinery/pkg/version,\
			// k8s.io/api/core/v1 \
			// github.com/apoxy-dev/apoxy/api/core/v1alpha,\
			//  -O zz_generated.openapi --output-package api/generated -h /dev/null
			WithOpenAPIDefinitions("apoxy", "0.1.0", apoxyopenapi.GetOpenAPIDefinitions).
			WithResourceAndStorage(&corev1alpha.Proxy{}, kineStore).
			WithResourceAndStorage(&corev1alpha.Address{}, kineStore).
			WithResourceAndStorage(&corev1alpha.Domain{}, kineStore).
			WithResourceAndStorage(&corev1alpha.TunnelNode{}, kineStore).
			WithResourceAndStorage(&corev1alpha.Backend{}, kineStore).
			WithResourceAndStorage(&ctrlv1alpha1.Proxy{}, kineStore).
			WithResourceAndStorage(&policyv1alpha1.RateLimit{}, kineStore).
			WithResourceAndStorage(&extensionsv1alpha1.EdgeFunction{}, kineStore).
			WithResourceAndStorage(&gatewayv1.GatewayClass{}, kineStore).
			WithResourceAndStorage(&gatewayv1.Gateway{}, kineStore).
			WithResourceAndStorage(&gatewayv1.HTTPRoute{}, kineStore).
			WithResourceAndStorage(&gatewayv1.GRPCRoute{}, kineStore).
			DisableAuthorization().
			WithOptionsFns(func(o *builder.ServerOptions) *builder.ServerOptions {
				o.StdErr = io.Discard
				o.StdOut = io.Discard

				o.RecommendedOptions.CoreAPI = nil
				o.RecommendedOptions.Admission = nil
				o.RecommendedOptions.Authentication = nil
				o.RecommendedOptions.Authorization = nil

				o.RecommendedOptions.SecureServing = &apiserveropts.SecureServingOptionsWithLoopback{
					SecureServingOptions: &apiserveropts.SecureServingOptions{
						BindAddress: netutils.ParseIPSloppy("0.0.0.0"),
						BindPort:    443,
						ServerCert: apiserveropts.GeneratableKeyCert{
							PairName:      dOpts.certPairName,
							CertDirectory: dOpts.certDir,
						},
					},
				}

				if dOpts.enableInClusterAuth {
					o.RecommendedOptions.Authentication = apiserveropts.NewDelegatingAuthenticationOptions()
					o.RecommendedOptions.Authentication.RemoteKubeConfigFileOptional = true

					o.RecommendedOptions.Authorization = apiserveropts.NewDelegatingAuthorizationOptions()
					o.RecommendedOptions.Authorization.RemoteKubeConfigFileOptional = true
					o.RecommendedOptions.Authorization.AlwaysAllowPaths = []string{"healthz"}
					o.RecommendedOptions.Authorization.AlwaysAllowGroups = []string{
						user.SystemPrivilegedGroup,
					}
				} else {
					o.RecommendedOptions.Authentication = nil
					o.RecommendedOptions.Authorization = nil
				}

				return o
			}).
			WithConfigFns(func(c *apiserver.RecommendedConfig) *apiserver.RecommendedConfig {
				// TODO(dilyevsky): Figure out how to make the listener flexible.
				// c.SecureServing.Listener = lst

				c.ClientConfig = dOpts.clientConfig
				c.SharedInformerFactory = informers.NewSharedInformerFactory(
					kubernetes.NewForConfigOrDie(c.ClientConfig),
					0,
				)
				c.FlowControl = nil

				if dOpts.enableSimpleAuth {
					c.Authentication.Authenticator = simpleAuth
					c.Authorization.Authorizer = authorizerfactory.NewAlwaysAllowAuthorizer()
				}

				return c
			}).
			WithoutEtcd().
			Execute(); err != nil {
			readyCh <- err
		}
	}()
	go func() {
		if err := waitForReadyz("https://127.0.0.1:443", 30*time.Second); err != nil {
			log.Fatalf("Failed to wait for APIServer: %v", err)
		}
		log.Infof("APIServer is ready")
		readyCh <- nil
	}()

	log.Infof("Waiting for APIServer...")

	select {
	case <-ctx.Done():
		log.Fatalf("Context cancelled while while waiting for APIServer: %v", ctx.Err())
	case err, ok := <-readyCh:
		if !ok {
			return nil, errors.New("APIServer failed to start")
		}
		if err != nil {
			return nil, fmt.Errorf("APIServer failed to start: %v", err)
		}
	}

	certSrc, err := newSelfSignedCert()
	if err != nil {
		return nil, fmt.Errorf("failed to generate self-signed certificate: %v", err)
	}
	whSrvOpts := webhook.Options{
		TLSOpts: []func(*tls.Config){
			func(cfg *tls.Config) {
				cfg.GetCertificate = certSrc.GetCertificate
			},
		},
	}

	mgr, err := ctrl.NewManager(dOpts.clientConfig, ctrl.Options{
		Scheme:         scheme,
		LeaderElection: false,
		WebhookServer:  webhook.NewServer(whSrvOpts),
	})
	if err != nil {
		return nil, fmt.Errorf("unable to start manager: %v", err)
	}

	return mgr, nil
}
