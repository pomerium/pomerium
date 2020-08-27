package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/pomerium/internal/encoding/jws"
)

type stringSlice []string

func (i *stringSlice) String() string {
	return fmt.Sprint(*i)
}

func (i *stringSlice) Set(value string) error {
	if len(*i) > 0 {
		return errors.New("already set")
	}
	for _, dt := range strings.Split(value, ",") {
		*i = append(*i, dt)
	}
	return nil
}

func (i *stringSlice) Type() string {
	return "slice"
}

type serviceAccount struct {
	// Standard claims (as specified in RFC 7519).
	jwt.Claims
	// Pomerium claims (not standard claims)
	Email             string   `json:"email"`
	Groups            []string `json:"groups,omitempty"`
	User              string   `json:"user,omitempty"`
	ImpersonateEmail  string   `json:"impersonate_email,omitempty"`
	ImpersonateGroups []string `json:"impersonate_groups,omitempty"`
}

var serviceAccountOptions struct {
	aud               stringSlice
	groups            stringSlice
	impersonateGroups stringSlice
	expiry            time.Duration
	serviceAccount    serviceAccount
}

func init() {
	flags := serviceAccountCmd.PersistentFlags()
	flags.StringVar(&serviceAccountOptions.serviceAccount.Email, "email", "", "Email")
	flags.StringVar(&serviceAccountOptions.serviceAccount.ImpersonateEmail, "impersonate_email", "", "Impersonation Email (optional)")
	flags.StringVar(&serviceAccountOptions.serviceAccount.Issuer, "iss", "", "Issuing Server (e.g authenticate.int.pomerium.io)")
	flags.StringVar(&serviceAccountOptions.serviceAccount.Subject, "sub", "", "Subject (typically User's GUID)")
	flags.StringVar(&serviceAccountOptions.serviceAccount.User, "user", "", "User (typically User's GUID)")
	flags.Var(&serviceAccountOptions.aud, "aud", "Audience (e.g. httpbin.int.pomerium.io,prometheus.int.pomerium.io)")
	flags.Var(&serviceAccountOptions.groups, "groups", "Groups (e.g. admins@pomerium.io,users@pomerium.io)")
	flags.Var(&serviceAccountOptions.impersonateGroups, "impersonate_groups", "Impersonation Groups (optional)")
	flags.DurationVar(&serviceAccountOptions.expiry, "expiry", time.Hour, "Expiry")
	rootCmd.AddCommand(serviceAccountCmd)
}

var serviceAccountCmd = &cobra.Command{
	Use:   "service-account",
	Short: "generates a pomerium service account from a shared key.",
	RunE: func(cmd *cobra.Command, args []string) error {
		// hydrate our session
		serviceAccountOptions.serviceAccount.Audience = jwt.Audience(serviceAccountOptions.aud)
		serviceAccountOptions.serviceAccount.Groups = []string(serviceAccountOptions.groups)
		serviceAccountOptions.serviceAccount.ImpersonateGroups = []string(serviceAccountOptions.impersonateGroups)
		serviceAccountOptions.serviceAccount.Expiry = jwt.NewNumericDate(time.Now().Add(serviceAccountOptions.expiry))
		serviceAccountOptions.serviceAccount.IssuedAt = jwt.NewNumericDate(time.Now())
		serviceAccountOptions.serviceAccount.NotBefore = jwt.NewNumericDate(time.Now())

		var sharedKey string
		if len(args) == 1 {
			sharedKey = args[0]
		} else if k := os.Getenv("POMERIUM_SHARED_KEY"); k != "" {
			sharedKey = k
		} else {
			fmt.Print("Enter base64 encoded shared key >")
			scanner := bufio.NewScanner(os.Stdin)
			scanner.Scan()
			sharedKey = scanner.Text()
		}

		if sharedKey == "" {
			return errors.New("shared key required")
		}

		if serviceAccountOptions.serviceAccount.Email == "" {
			return errors.New("email is required")
		}

		if len(serviceAccountOptions.serviceAccount.Audience) == 0 {
			return errors.New("aud is required")
		}

		if serviceAccountOptions.serviceAccount.Issuer == "" {
			return errors.New("iss is required")
		}
		encoder, err := jws.NewHS256Signer([]byte(sharedKey), serviceAccountOptions.serviceAccount.Issuer)
		if err != nil {
			return fmt.Errorf("bad shared key: %w", err)
		}
		raw, err := encoder.Marshal(serviceAccountOptions.serviceAccount)
		if err != nil {
			return fmt.Errorf("bad encode: %w", err)
		}
		fmt.Fprintf(os.Stdout, "%s", raw)
		return nil
	},
}
