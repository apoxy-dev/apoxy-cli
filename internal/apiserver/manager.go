package apiserver

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"math/big"
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
	"k8s.io/apiserver/pkg/authentication/request/union"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizerfactory"
	apiserver "k8s.io/apiserver/pkg/server"
	"k8s.io/apiserver/pkg/server/dynamiccertificates"
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

const (
	apiserverCA   = "apoxy-apiserver-ca"
	apiserverUser = "apoxy-apiserver"
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

func generateSelfSignedCerts(certDir, pairName string) (certFile, keyFile string, caFile string, err error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate private key: %w", err)
	}
	cfg := certutil.Config{
		CommonName: apiserverCA,
	}
	caCert, err := certutil.NewSelfSignedCACert(cfg, caKey)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate self-signed certificate: %w", err)
	}

	certKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate private key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).SetInt64(math.MaxInt64-1))
	if err != nil {
		return "", "", "", fmt.Errorf("failed to generate serial number: %w", err)
	}
	serial = new(big.Int).Add(serial, big.NewInt(1))
	validFrom := time.Now().Add(-time.Hour)
	template := x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName: apiserverUser,
		},

		NotBefore: validFrom,
		NotAfter:  validFrom.Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, certKey.Public(), caKey)
	if err != nil {
		return "", "", "", fmt.Errorf("failed to create certificate: %w", err)
	}

	if err := os.MkdirAll(certDir, 0755); err != nil {
		return "", "", "", fmt.Errorf("failed to create certificate directory: %w", err)
	}
	certFile = filepath.Join(certDir, pairName+".crt")
	keyFile = filepath.Join(certDir, pairName+".key")
	caFile = filepath.Join(certDir, "ca.crt")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes}), 0644); err != nil {
		return "", "", "", fmt.Errorf("failed to write certificate: %w", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(certKey)}), 0600); err != nil {
		return "", "", "", fmt.Errorf("failed to write private key: %w", err)
	}
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCert.Raw}), 0644); err != nil {
		return "", "", "", fmt.Errorf("failed to write CA certificate: %w", err)
	}
	return certFile, keyFile, caFile, nil
}

type certSource struct {
	cert, key []byte
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
	sqliteConnArgs        map[string]string
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

// WithSQLiteConnArgs sets the SQLite connection arguments.
func WithInMemorySQLite() Option {
	return func(o *options) {
		o.sqlitePath = "file::memory:"
	}
}

// WithCerts sets the certificate pair name and directory.
func WithCerts(certPairName, certDir string) Option {
	return func(o *options) {
		o.certPairName = certPairName
		o.certDir = certDir
	}
}

// WithSQLiteConnArgs sets the SQLite connection arguments.
// The default values are:
//
//	cache=shared
//	_journal_mode=WAL
//	_busy_timeout=30000
func WithSQLiteConnArgs(args map[string]string) Option {
	return func(o *options) {
		o.sqliteConnArgs = args
	}
}

func encodeSQLiteConnArgs(args map[string]string) string {
	var buf strings.Builder
	for k, v := range args {
		if buf.Len() > 0 {
			buf.WriteString("&")
		}
		buf.WriteString(k)
		buf.WriteString("=")
		buf.WriteString(v)
	}
	return buf.String()
}

// defaultOptions returns default options.
func defaultOptions() *options {
	return &options{
		clientConfig:        NewClientConfig(),
		enableSimpleAuth:    false,
		enableInClusterAuth: false,
		sqlitePath:          config.ApoxyDir() + "/apoxy.db",
		sqliteConnArgs: map[string]string{
			"cache":         "shared",
			"_journal_mode": "WAL",
			"_busy_timeout": "30000",
		},
		certDir:      "",
		certPairName: "tls",
	}
}

// Manager manages APIServer instance as well as built-in controllers.
type Manager struct {
	ReadyCh chan error

	manager manager.Manager
}

// New creates a new API server manager.
func New() *Manager {
	return &Manager{
		ReadyCh: make(chan error),
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
		m.ReadyCh <- err
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

func (m *Manager) ClientConfig() *rest.Config {
	return m.manager.GetConfig()
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

	var (
		genCert         dynamiccertificates.CertKeyContentProvider
		localClientAuth authenticator.Request

		serverCertFile string
		serverKeyFile  string
		serverCAFile   string

		err error
	)

	if dOpts.certDir == "" {
		log.Infof("No certificate directory provided. Creating self-signed certificate...")
		certDir, err := os.MkdirTemp(os.TempDir(), "apoxy-cert-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temporary directory for self-signed certificate: %v", err)
		}
		dOpts.certDir = certDir
		serverCertFile, serverKeyFile, serverCAFile, err = generateSelfSignedCerts(dOpts.certDir, dOpts.certPairName)
		if err != nil {
			return nil, fmt.Errorf("failed to generate self-signed certificate: %v", err)
		}
	} else {
		log.Infof("Using certificate pair name %q and directory %q", dOpts.certPairName, dOpts.certDir)
		serverCertFile := filepath.Join(dOpts.certDir, dOpts.certPairName+".crt")
		if _, err := os.Stat(serverCertFile); err != nil {
			return nil, fmt.Errorf("failed to stat server certificate file %q: %v", serverCertFile, err)
		}
		serverKeyFile := filepath.Join(dOpts.certDir, dOpts.certPairName+".key")
		if _, err := os.Stat(serverKeyFile); err != nil {
			return nil, fmt.Errorf("failed to stat server key file %q: %v", serverKeyFile, err)
		}
		serverCAFile := filepath.Join(dOpts.certDir, "ca.crt")
		if _, err := os.Stat(serverCAFile); err != nil {
			return nil, fmt.Errorf("failed to stat server CA file %q: %v", serverCAFile, err)
		}
	}

	if dOpts.enableSimpleAuth {
		w := auth.NewTransportWrapperFunc(apiserverUser, []string{user.SystemPrivilegedGroup}, nil)
		dOpts.clientConfig = NewClientConfig(WithTransportWrapper(w))
	} else if dOpts.enableInClusterAuth {
		log.Infof("Using in-cluster configuration")

		genCert, err = dynamiccertificates.NewDynamicServingContentFromFiles("serving-cert", serverCertFile, serverKeyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create dynamic serving content: %v", err)
		}

		// Generate self-signed client certificate for local client.
		tmpDir, err := os.MkdirTemp(os.TempDir(), "apoxy-client-certs-*")
		if err != nil {
			return nil, fmt.Errorf("failed to create temp dir: %v", err)
		}
		clientCertFile, clientKeyFile, clientCAFile, err := generateSelfSignedCerts(tmpDir, "client")
		if err != nil {
			return nil, fmt.Errorf("failed to generate self-signed certificate: %v", err)
		}
		localClientAuth, err = auth.NewX509Authenticator(clientCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to create x509 authenticator: %v", err)
		}
		dOpts.clientConfig = NewClientConfig(
			WithClientTLSConfig(rest.TLSClientConfig{
				CertFile: clientCertFile,
				KeyFile:  clientKeyFile,
				CAFile:   serverCAFile,
			}),
		)
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
		sqliteConn := "sqlite://" + dOpts.sqlitePath
		connArgs := encodeSQLiteConnArgs(dOpts.sqliteConnArgs)
		if connArgs != "" {
			sqliteConn += "?" + connArgs
		}
		log.Debugf("Using SQLite connection: %s", sqliteConn)
		kineStore, err := NewKineStorage(ctx, sqliteConn)
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
							GeneratedCert: genCert,
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
					// For simple auth, we use a header authenticator and an always allow authorizer.
					c.Authentication.Authenticator = auth.NewHeaderAuthenticator()
					c.Authorization.Authorizer = authorizerfactory.NewAlwaysAllowAuthorizer()
				} else if dOpts.enableInClusterAuth {
					// For in-cluster auth, we use the default delegating (to the kube-apiserver)
					// authenticator and authorizer.
					// The union authenticator will try authenticators in order until one succeeds.
					c.Authentication.Authenticator = union.New(
						localClientAuth,
						c.Authentication.Authenticator,
					)
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

	whSrvOpts := webhook.Options{
		CertDir:  dOpts.certDir,
		CertName: dOpts.certPairName + ".crt",
		KeyName:  dOpts.certPairName + ".key",
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
