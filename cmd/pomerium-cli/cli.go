package main

import (
	"bufio"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/square/go-jose.v2/jwt"

	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/pkg/grpc"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/user"
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
	aud                     stringSlice
	groups                  stringSlice
	impersonateGroups       stringSlice
	expiry                  time.Duration
	serviceAccount          serviceAccount
	dataBrokerURL           string
	overrideCertificateName string
	ca                      string
	caFile                  string
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
	flags.StringVar(&serviceAccountOptions.dataBrokerURL, "databroker-url", "http://localhost:5443", "the URL of the databroker used to store service accounts")
	flags.StringVar(&serviceAccountOptions.overrideCertificateName, "override-certificate-name", "", "override the certificate name")
	flags.StringVar(&serviceAccountOptions.ca, "certificate-authority", "", "custom certificate authority")
	flags.StringVar(&serviceAccountOptions.caFile, "certificate-authority-file", "", "customer certificate authority file")
	rootCmd.AddCommand(serviceAccountCmd)
}

var serviceAccountCmd = &cobra.Command{
	Use:   "service-account",
	Short: "generates a pomerium service account from a shared key.",
	RunE: func(cmd *cobra.Command, args []string) error {
		l := zerolog.Nop()
		log.SetLogger(&l)

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

		dataBrokerURL, err := url.Parse(serviceAccountOptions.dataBrokerURL)
		if err != nil {
			return fmt.Errorf("invalid databroker url: %w", err)
		}

		rawSharedKey, _ := base64.StdEncoding.DecodeString(sharedKey)

		cc, err := grpc.GetGRPCClientConn("databroker", &grpc.Options{
			Addr:                    dataBrokerURL,
			OverrideCertificateName: serviceAccountOptions.overrideCertificateName,
			CA:                      serviceAccountOptions.ca,
			CAFile:                  serviceAccountOptions.caFile,
			WithInsecure:            !strings.HasSuffix(dataBrokerURL.Scheme, "s"),
			SignedJWTKey:            rawSharedKey,
		})
		if err != nil {
			return fmt.Errorf("error creating databroker connection: %w", err)
		}
		defer cc.Close()

		sa := &user.ServiceAccount{
			Id:        uuid.New().String(),
			UserId:    serviceAccountOptions.serviceAccount.User,
			ExpiresAt: timestamppb.New(serviceAccountOptions.serviceAccount.Expiry.Time()),
			IssuedAt:  timestamppb.Now(),
		}
		_, err = user.SetServiceAccount(context.Background(), databroker.NewDataBrokerServiceClient(cc), sa)
		if err != nil {
			return fmt.Errorf("error saving service account: %w", err)
		}
		serviceAccountOptions.serviceAccount.ID = sa.GetId()

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
