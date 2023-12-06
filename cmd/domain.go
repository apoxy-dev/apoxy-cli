package cmd

import (
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
		Header: buildDomainHeader(),
		Rows: pretty.Rows{
			buildDomainRow(r),
		},
	}
	t.Print()
}

func buildDomainHeader() pretty.Header {
	return pretty.Header{
		"NAME",
		"HOSTNAMES",
		"STATUS",
		"AGE",
	}
}

func buildDomainRow(r *v1alpha.Domain) []interface{} {
	if r.Spec.Style == v1alpha.DomainStyleMagic {
		return []interface{}{
			r.Name,
			fmt.Sprintf("%s.apoxy.io", r.Spec.MagicKey),
			r.Status.Phase,
			pretty.SinceString(r.CreationTimestamp.Time),
		}
	}
	return []interface{}{
		r.Name,
		strings.Join(r.Spec.Hostnames, ", "),
		r.Status.Phase,
		pretty.SinceString(r.CreationTimestamp.Time),
	}
}

func getOrCreateMagicProxy(c *rest.APIClient, name string) error {
	r, err := c.Proxy().ListWithOptions(metav1.ListOptions{
		LabelSelector: "magic=yes",
	})
	if err != nil {
		return err
	}
	if len(r.Items) > 0 {
		return nil
	}
	p, err := c.Proxy().Create(&v1alpha.Proxy{
		ObjectMeta: metav1.ObjectMeta{
			Name: name,
			Labels: map[string]string{
				"magic": "yes",
			},
		},
		Spec: v1alpha.ProxySpec{
			DynamicForwardProxy: true,
		},
	})
	if err != nil {
		return err
	}
	fmt.Printf("proxy %q created\n", p.Name)
	return nil
}

func GetDomain(name string) error {
	c, err := defaultAPIClient()
	if err != nil {
		return err
	}
	r, err := c.Domain().Get(name)
	if err != nil {
		return err
	}
	fmtDomain(r)
	return nil
}

func ListDomains() error {
	c, err := defaultAPIClient()
	if err != nil {
		return err
	}
	r, err := c.Domain().List()
	if err != nil {
		return err
	}
	t := pretty.Table{
		Header: buildDomainHeader(),
	}
	for _, p := range r.Items {
		t.Rows = append(t.Rows, buildDomainRow(&p))
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
		return ListDomains()
	},
}

var listProxies bool

// getDomainCmd represents the get domain command
var getDomainCmd = &cobra.Command{
	Use:       "get <name>",
	Short:     "Get domain objects",
	ValidArgs: []string{"name"},
	Args:      cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		if listProxies {
			c, err := defaultAPIClient()
			if err != nil {
				return err
			}
			r, err := c.Domain().Get(args[0])
			if err != nil {
				return err
			}
			return ListProxies(metav1.ListOptions{
				LabelSelector: metav1.FormatLabelSelector(&r.Spec.Selector),
			})
		}
		return GetDomain(args[0])
	},
}

// listDomainCmd represents the list domain command
var listDomainCmd = &cobra.Command{
	Use:   "list",
	Short: "List domain objects",
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		return ListDomains()
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
			if err = getOrCreateMagicProxy(c, domainName); err != nil {
				return err
			}
			d, err := c.Domain().Create(&v1alpha.Domain{
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
			})
			if err != nil {
				return err
			}
			fmt.Printf("domain %q created\n", d.Name)
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

		r, err := c.Domain().Create(domain)
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
		if err = c.Domain().Delete(args[0]); err != nil {
			return err
		}
		fmt.Printf("domain %q deleted\n", args[0])
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
		BoolVarP(&listProxies, "proxies", "p", false, "List the proxies this domain points to.")
	// TODO: add flags for domain config as raw envoy config

	domainCmd.AddCommand(getDomainCmd, listDomainCmd, createDomainCmd, deleteDomainCmd)
	rootCmd.AddCommand(domainCmd)
}
