package config

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/getsentry/sentry-go"
	"github.com/google/uuid"
	"github.com/pkg/browser"
	"golang.org/x/exp/slog"
	"k8s.io/client-go/rest"

	configv1alpha1 "github.com/apoxy-dev/apoxy-cli/api/config/v1alpha1"
	"github.com/apoxy-dev/apoxy-cli/web"
)

type authContext struct {
	APIKey    string
	ProjectID uuid.UUID
}

type Authenticator struct {
	cfg    *configv1alpha1.Config
	authCh chan authContext
}

func NewAuthenticator(cfg *configv1alpha1.Config) *Authenticator {
	return &Authenticator{
		cfg: cfg,
	}
}

func (a *Authenticator) Check() (bool, error) {
	c, err := DefaultAPIClient()
	if err != nil {
		return true, err
	}

	if c.BaseHost != "" {
		resp, err := c.SendRequest(http.MethodPost, "/v1/terra/check", nil)
		if err != nil {
			return true, err
		}

		slog.Debug("/v1/terra/check returned", "status", resp.StatusCode)
		if resp.StatusCode != 200 {
			return false, nil
		}
	}

	if c.RESTConfig != nil {
		httpC, err := rest.HTTPClientFor(c.RESTConfig)
		if err != nil {
			return true, err
		}
		req, err := http.NewRequest("HEAD", c.RESTConfig.Host, nil)
		if err != nil {
			return true, err
		}
		resp, err := httpC.Do(req)
		if err != nil {
			return true, err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return false, nil
		}
	}

	return true, nil
}

func (a *Authenticator) healthzHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "OK")
}

func (a *Authenticator) handler(w http.ResponseWriter, r *http.Request) {
	key := r.URL.Query().Get("key")
	projectID := r.URL.Query().Get("project")
	slog.Debug("API key received", "APIKey", key, "ProjectID", projectID)
	go func() {
		time.Sleep(2 * time.Second)
		pUUID, err := uuid.Parse(projectID)
		if err != nil {
			slog.Error("Failed to parse project ID", "error", err)
			return
		}
		a.authCh <- authContext{APIKey: key, ProjectID: pUUID}
	}()
	fmt.Fprintf(w, web.LoginOKHTML)
}

func (a *Authenticator) awaitHealthy(port int) error {
	url := fmt.Sprintf("http://localhost:%d/healthz", port)
	client := http.Client{
		Timeout: 5 * time.Second,
	}
	attempt := 0
	for {
		resp, err := client.Get(url)
		if err == nil {
			defer resp.Body.Close()
			break
		}
		time.Sleep(1 * time.Second)
		attempt++
		if attempt > 10 {
			return fmt.Errorf("Failed to health check server")
		}
	}
	return nil
}

func (a *Authenticator) launchServer() int {
	// Create a listener on a random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal("Error starting listener: ", err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	go func() {
		defer listener.Close()
		http.HandleFunc("/", a.handler)
		http.HandleFunc("/healthz", a.healthzHandler)
		slog.Debug(fmt.Sprintf("Server listening on port %d", port))
		err = http.Serve(listener, nil)
		if err != nil {
			slog.Error("Error starting server", slog.Any("error", err))
		}
	}()
	if err := a.awaitHealthy(port); err != nil {
		slog.Error("Error starting server", slog.Any("error", err))
		sentry.CaptureMessage("auth redirect server failed to start")
	}
	return port
}

func (a *Authenticator) Authenticate() {
	a.authCh = make(chan authContext)
	port := a.launchServer()
	next := url.QueryEscape(fmt.Sprintf("http://localhost:%d/auth", port))
	host := a.cfg.DashboardURL
	if host == "" {
		host = DefaultConfig.DashboardURL
	}
	authUrl := fmt.Sprintf("%s/auth/cli?next=%s", host, next)
	browser.OpenURL(authUrl)
	fmt.Println("If a browser window did not open, you may authenticate using the following URL:")
	fmt.Printf("\n\t%s\n\n", authUrl)
	key := <-a.authCh

	var projectUpdated bool
	for i, p := range a.cfg.Projects {
		if p.ID == a.cfg.CurrentProject {
			a.cfg.Projects[i].APIKey = key.APIKey
			projectUpdated = true
			break
		}
	}
	if !projectUpdated {
		slog.Error("Failed to update project", "ProjectID", a.cfg.CurrentProject)
		return
	}

	slog.Debug("API key set", "APIKey", key.APIKey, "ProjectID", a.cfg.CurrentProject)
	fmt.Println("Login Succcessful!")
	return
}
