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

	"k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	"k8s.io/apiserver/pkg/features"
	apiserver "k8s.io/apiserver/pkg/server"
	apiserveropts "k8s.io/apiserver/pkg/server/options"
	"k8s.io/apiserver/pkg/util/feature"
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
	"github.com/apoxy-dev/apoxy-cli/internal/log"
	"github.com/sirupsen/logrus"

	ctrlv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/controllers/v1alpha1"
	corev1alpha "github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	extensionsv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/extensions/v1alpha1"
	apoxyopenapi "github.com/apoxy-dev/apoxy-cli/api/generated"
	policyv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/policy/v1alpha1"
)

var scheme = runtime.NewScheme()

func init() {
	utilruntime.Must(corev1alpha.AddToScheme(scheme))
	utilruntime.Must(ctrlv1alpha1.AddToScheme(scheme))
	utilruntime.Must(policyv1alpha1.AddToScheme(scheme))
	utilruntime.Must(extensionsv1alpha1.AddToScheme(scheme))
	feature.DefaultMutableFeatureGate.Set(string(features.APIPriorityAndFairness) + "=false")
}

func waitForReadyz(url string, timeout time.Duration) error {
	t := time.NewTimer(timeout)
	for {
		client := &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
			Timeout: timeout,
		}

		resp, err := client.Get(url + "/readyz")
		if err == nil && resp.StatusCode == http.StatusOK {
			return nil
		}

		log.Debugf("failed readyz request: %v", err)

		select {
		case <-t.C:
			return errors.New("timed out waiting for readyz")
		case <-time.After(100 * time.Millisecond):
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
	enableAuth            bool
	sqlitePath            string
	certPairName, certDir string
}

// WithClientConfig sets the client configuration.
func WithClientConfig(cfg *rest.Config) Option {
	return func(o *options) {
		o.clientConfig = cfg
	}
}

// WithAuth enables authentication.
func WithAuth() Option {
	return func(o *options) {
		o.enableAuth = true
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

// defaultOptions returns default options.
func defaultOptions() *options {
	return &options{
		clientConfig: NewLocalClientConfig("localhost"),
		enableAuth:   false,
		sqlitePath:   config.ApoxyDir() + "/apoxy.db",
		certPairName: "",
		certDir:      "",
	}
}

// Start starts the API server and returns the manager (that can be used to start the controller
// manager). The manager must be started by the caller.
func Start(
	ctx context.Context,
	opts ...Option,
) (manager.Manager, error) {
	dOpts := defaultOptions()
	for _, o := range opts {
		o(dOpts)
	}
	// Reset flags. APIServer cmd expects its own flagset.
	flag.CommandLine = flag.NewFlagSet("apiserver", flag.ExitOnError)
	os.Args = append([]string{os.Args[0]}, flag.Args()...) // Keep non-flag arguments.

	sAuth, err := auth.NewHeaderAuthenticator()
	if err != nil {
		log.Fatalf("Failed to create authenticator: %v", err)
	}

	l := log.New(config.Verbose)
	ctrl.SetLogger(l)
	klog.SetLogger(l)
	// Disables useless kine logging.
	logrus.SetOutput(io.Discard)

	readyCh := make(chan struct{})
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
			WithResourceAndStorage(&corev1alpha.Proxy{}, NewKineStorage(ctx, "sqlite://"+dOpts.sqlitePath)).
			WithResourceAndStorage(&corev1alpha.Address{}, NewKineStorage(ctx, "sqlite://"+dOpts.sqlitePath)).
			WithResourceAndStorage(&corev1alpha.Domain{}, NewKineStorage(ctx, "sqlite://"+dOpts.sqlitePath)).
			WithResourceAndStorage(&corev1alpha.TunnelNode{}, NewKineStorage(ctx, "sqlite://"+dOpts.sqlitePath)).
			WithResourceAndStorage(&ctrlv1alpha1.Proxy{}, NewKineStorage(ctx, "sqlite://"+dOpts.sqlitePath)).
			WithResourceAndStorage(&policyv1alpha1.RateLimit{}, NewKineStorage(ctx, "sqlite://"+dOpts.sqlitePath)).
			WithResourceAndStorage(&extensionsv1alpha1.EdgeFunction{}, NewKineStorage(ctx, "sqlite://"+dOpts.sqlitePath)).
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

				// if *enableAuth {
				//	o.RecommendedOptions.Authentication = options.NewDelegatingAuthenticationOptions()
				//	o.RecommendedOptions.Authentication.RemoteKubeConfigFileOptional = true

				//	o.RecommendedOptions.Authorization = options.NewDelegatingAuthorizationOptions()
				//	o.RecommendedOptions.Authorization.RemoteKubeConfigFileOptional = true
				//	o.RecommendedOptions.Authorization.AlwaysAllowPaths = []string{"healthz"}
				//	o.RecommendedOptions.Authorization.AlwaysAllowGroups = []string{user.SystemPrivilegedGroup, "apoxy"}
				//} else {
				//	o.RecommendedOptions.Authentication = nil
				//	o.RecommendedOptions.Authorization = nil
				//}

				return o
			}).
			WithConfigFns(func(c *apiserver.RecommendedConfig) *apiserver.RecommendedConfig {
				// TODO(dilyevsky): Figure out how to make the listener flexible.
				// c.SecureServing.Listener = lst

				c.ClientConfig = dOpts.clientConfig

				if dOpts.enableAuth {
					// These are matched in order, so we want to match the header request
					// before falling back to anonymous.
					c.Authentication.Authenticator = sAuth
					c.Authorization.Authorizer = authorizerfactory.NewAlwaysAllowAuthorizer()
				}
				return c
			}).
			WithoutEtcd().
			Execute(); err != nil {
			log.Fatalf("Failed to start APIServer: %v", err)
		}
	}()
	go func() {
		if err := waitForReadyz("https://127.0.0.1:443", 5*time.Second); err != nil {
			log.Fatalf("Failed to wait for APIServer: %v", err)
		}
		log.Infof("APIServer is ready")
		readyCh <- struct{}{}
	}()

	log.Infof("Waiting for APIServer...")

	select {
	case <-ctx.Done():
		log.Fatalf("Context cancelled while while waiting for APIServer: %v", ctx.Err())
	case <-readyCh:
	}

	certSrc, err := newSelfSignedCert()
	if err != nil {
		log.Fatalf("Failed to generate self-signed certificate: %v", err)
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
		log.Fatalf("unable to start manager: %v", err)
	}

	return mgr, nil
}
