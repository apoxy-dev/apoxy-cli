package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/goombaio/namegenerator"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slog"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/apoxy-dev/apoxy-cli/api/core/v1alpha"
	"github.com/apoxy-dev/apoxy-cli/pretty"
	"github.com/apoxy-dev/apoxy-cli/rest"
)

func fmtDomain(r *v1alpha.Domain) {
	t := pretty.Table{
		Header: buildDomainHeader(false),
		Rows: pretty.Rows{
			buildDomainRow(r, false),
		},
	}
	t.Print()
}

func buildDomainHeader(labels bool) pretty.Header {
	if labels {
		return pretty.Header{
			"NAME",
			"HOSTNAMES",
			"STATUS",
			"AGE",
			"LABELS",
		}
	}
	return pretty.Header{
		"NAME",
		"HOSTNAMES",
		"STATUS",
		"AGE",
	}
}

func buildDomainRow(r *v1alpha.Domain, labels bool) (res []interface{}) {
	if r.Spec.Style == v1alpha.DomainStyleMagic {
		res = []interface{}{
			r.Name,
			fmt.Sprintf("%s.apoxy.io", r.Spec.MagicKey),
			r.Status.Phase,
			pretty.SinceString(r.CreationTimestamp.Time),
		}
	} else {
		res = []interface{}{
			r.Name,
			strings.Join(r.Spec.Hostnames, ", "),
			r.Status.Phase,
			pretty.SinceString(r.CreationTimestamp.Time),
		}
	}
	if labels {
		res = append(res, labelsToString(r.Labels))
	}
	return
}

func getOrCreateMagicProxy(ctx context.Context, c *rest.APIClient, name string) error {
	r, err := c.CoreV1alpha().Proxies().List(ctx, metav1.ListOptions{
		LabelSelector: "magic=yes",
	})
	if err != nil {
		return err
	}
	if len(r.Items) > 0 {
		return nil
	}
	p, err := c.CoreV1alpha().Proxies().Create(ctx, &v1alpha.Proxy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"magic": "yes",
			},
		},
		Spec: v1alpha.ProxySpec{
			Type:                v1alpha.ProxyTypeEnvoy,
			Provider:            v1alpha.InfraProviderCloud,
			DynamicForwardProxy: true,
		},
	}, metav1.CreateOptions{})
	if err != nil {
		return err
	}
	fmt.Printf("proxy %q created\n", p.Name)
	return nil
}

func GetDomain(ctx context.Context, name string) error {
	c, err := defaultAPIClient()
	if err != nil {
		return err
	}
	r, err := c.CoreV1alpha().Domains().Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return err
	}
	fmtDomain(r)
	return nil
}

var showDomainLabels bool

func ListDomains(ctx context.Context) error {
	c, err := defaultAPIClient()
	if err != nil {
		return err
	}
	r, err := c.CoreV1alpha().Domains().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	t := pretty.Table{
		Header: buildDomainHeader(showDomainLabels),
	}
	for _, p := range r.Items {
		t.Rows = append(t.Rows, buildDomainRow(&p, showDomainLabels))
	}
	t.Print()
	return nil
}

// domainCmd represents the domain command
var domainCmd = &cobra.Command{
	Use:     "domain",
	Short:   "Manage domain objects",
	Long:    `Expose proxies on your own domains or borrow one of ours to get going quickly.`,
	Aliases: []string{"d", "domains"},
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		return ListDomains(cmd.Context())
	},
}

var showProxies bool

// getDomainCmd represents the get domain command
var getDomainCmd = &cobra.Command{
	Use:       "get <name>",
	Short:     "Get domain objects",
	ValidArgs: []string{"name"},
	Args:      cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		if showProxies {
			c, err := defaultAPIClient()
			if err != nil {
				return err
			}
			r, err := c.CoreV1alpha().Domains().Get(cmd.Context(), args[0], metav1.GetOptions{})
			if err != nil {
				return err
			}
			return listProxies(cmd.Context(), c, metav1.ListOptions{
				LabelSelector: metav1.FormatLabelSelector(&r.Spec.Selector),
			})
		}
		return GetDomain(cmd.Context(), args[0])
	},
}

// listDomainCmd represents the list domain command
var listDomainCmd = &cobra.Command{
	Use:   "list",
	Short: "List domain objects",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		return ListDomains(cmd.Context())
	},
}

var (
	// domainFile is the file that contains the configuration to create.
	domainFile string
	// domainMagic is whether to create a new magic domain.
	domainMagic bool
	// domainName is the name of the new domain.
	domainName string
	// domainRandomName is whether to generate a random name for the new domain.
	domainRandomName bool
)

// createDomainCmd represents the create domain command
var createDomainCmd = &cobra.Command{
	Use:   "create [-f filename]",
	Short: "Create domain objects",
	Long:  `Create domain objects by providing a configuration as a file or via stdin.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Load the config to create from a file or stdin.
		var domainConfig string
		var err error
		stat, _ := os.Stdin.Stat()
		if stat.Mode()&os.ModeCharDevice == 0 {
			if domainFile != "" {
				return fmt.Errorf("cannot use --filename with stdin")
			}
			if domainName != "" {
				return fmt.Errorf("cannot use --name with stdin")
			}
			if domainRandomName {
				return fmt.Errorf("cannot use --random with a file")
			}
			if domainMagic {
				return fmt.Errorf("cannot use --magic with stdin")
			}
			domainConfig, err = readStdInAsString()
		} else if domainFile != "" {
			if domainName != "" {
				return fmt.Errorf("cannot use --name with a file")
			}
			if domainRandomName {
				return fmt.Errorf("cannot use --random with a file")
			}
			if domainMagic {
				return fmt.Errorf("cannot use --magic with a file")
			}
			domainConfig, err = readFileAsString(domainFile)
		} else if domainMagic {
			if domainName == "" {
				if domainRandomName {
					domainName = namegenerator.NewNameGenerator(time.Now().UTC().UnixNano()).Generate()
				} else {
					return fmt.Errorf("please provide a name via --name or use a random one with --random")
				}
			}
		} else {
			return fmt.Errorf("please provide a configuration via --filename or stdin, or use --magic")
		}
		if err != nil {
			return err
		}

		cmd.SilenceUsage = true

		c, err := defaultAPIClient()
		if err != nil {
			return err
		}

		if domainMagic {
			if err = getOrCreateMagicProxy(cmd.Context(), c, domainName); err != nil {
				return err
			}
			d, err := c.CoreV1alpha().Domains().Create(cmd.Context(), &v1alpha.Domain{
				ObjectMeta: metav1.ObjectMeta{
					Name: domainName,
				},
				Spec: v1alpha.DomainSpec{
					Selector: metav1.LabelSelector{
						MatchLabels: map[string]string{
							"magic": "yes",
						},
					},
					Style: v1alpha.DomainStyleMagic,
				},
			}, metav1.CreateOptions{})
			if err != nil {
				return err
			}
			gotMagicKey := false
			iteration := 1
			for !gotMagicKey {
				time.Sleep(time.Duration(iteration*250) * time.Millisecond)
				d, err = c.CoreV1alpha().Domains().Get(cmd.Context(), d.Name, metav1.GetOptions{})
				if err != nil {
					return err
				}
				gotMagicKey = d.Spec.MagicKey != ""
			}
			fmt.Printf("domain %q created\n", d.Name)
			fmt.Printf("%q is your magic key\n", d.Spec.MagicKey)
			return nil
		}

		// Parse domainConfig into a domain object.
		domain := &v1alpha.Domain{}
		domainJSON, err := yamlStringToJSONString(domainConfig)
		if err != nil {
			// Try assuming that the config is a JSON string?
			slog.Debug("failed to parse domain config as yaml - assuming input is JSON", "error", err)
			domainJSON = domainConfig
		}
		err = json.Unmarshal([]byte(domainJSON), domain)
		if err != nil {
			return err
		}

		r, err := c.CoreV1alpha().Domains().Create(cmd.Context(), domain, metav1.CreateOptions{})
		if err != nil {
			return err
		}
		fmt.Printf("domain %q created\n", r.Name)
		return nil
	},
}

// deleteDomainCmd represents the delete domain command
var deleteDomainCmd = &cobra.Command{
	Use:   "delete",
	Short: "Delete domain objects",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		c, err := defaultAPIClient()
		if err != nil {
			return err
		}
		for _, domain := range args {
			if err = c.CoreV1alpha().Domains().Delete(cmd.Context(), domain, metav1.DeleteOptions{}); err != nil {
				return err
			}
			fmt.Printf("domain %q deleted\n", domain)
		}
		return nil
	},
}

func init() {
	createDomainCmd.PersistentFlags().
		StringVarP(&domainFile, "filename", "f", "", "The file that contains the configuration to create.")
	createDomainCmd.PersistentFlags().
		BoolVar(&domainMagic, "magic", false, "Create a new magic domain.")
	createDomainCmd.PersistentFlags().
		StringVar(&domainName, "name", "", "A name for the new domain.")
	createDomainCmd.PersistentFlags().
		BoolVar(&domainRandomName, "random", false, "Generate a random name of the domain.")
	getDomainCmd.PersistentFlags().
		BoolVarP(&showProxies, "proxies", "p", false, "Show the proxies this domain points to.")
	listDomainCmd.PersistentFlags().
		BoolVar(&showDomainLabels, "show-labels", false, "Print the domain's labels.")
	// TODO: add flags for domain config as raw envoy config

	domainCmd.AddCommand(getDomainCmd, listDomainCmd, createDomainCmd, deleteDomainCmd)
	rootCmd.AddCommand(domainCmd)
}
