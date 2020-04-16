package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/pomerium/pomerium/internal/encoding/jws"
	"gopkg.in/square/go-jose.v2/jwt"
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

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "\n⛔️%s\n\n", err)
		printHelp(flags)
		os.Exit(1)
	}
	os.Exit(0)
}

var flags *flag.FlagSet

func run() error {
	var sa serviceAccount

	// temporary variables we will use to hydrate our service account
	// struct from basic types pulled in from our flags
	var (
		aud               stringSlice
		groups            stringSlice
		impersonateGroups stringSlice
		expiry            time.Duration
	)

	// set our JWT claims from the supplied CLI flags
	flags = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	flags.StringVar(&sa.Email, "email", "", "Email")
	flags.StringVar(&sa.ImpersonateEmail, "impersonate_email", "", "Impersonation Email (optional)")
	flags.StringVar(&sa.Issuer, "iss", "", "Issuing Server (e.g authenticate.int.pomerium.io)")
	flags.StringVar(&sa.Subject, "sub", "", "Subject (typically User's GUID)")
	flags.StringVar(&sa.User, "user", "", "User (typically User's GUID)")
	flags.Var(&aud, "aud", "Audience (e.g. httpbin.int.pomerium.io,prometheus.int.pomerium.io)")
	flags.Var(&groups, "groups", "Groups (e.g. admins@pomerium.io,users@pomerium.io)")
	flags.Var(&impersonateGroups, "impersonate_groups", "Impersonation Groups (optional)")
	flags.DurationVar(&expiry, "expiry", time.Hour, "Expiry")

	// hydrate the sessions non-primate types
	if err := flags.Parse(os.Args[1:]); err != nil {
		return err
	}
	sa.Audience = jwt.Audience(aud)
	sa.Groups = []string(groups)
	sa.ImpersonateGroups = []string(impersonateGroups)
	sa.Expiry = jwt.NewNumericDate(time.Now().Add(expiry))
	sa.IssuedAt = jwt.NewNumericDate(time.Now())
	sa.NotBefore = jwt.NewNumericDate(time.Now())
	var sharedKey string
	args := flags.Args()
	if len(args) == 1 {
		sharedKey = args[0]
	} else {
		fmt.Print("Enter base64 encoded shared key >")
		scanner := bufio.NewScanner(os.Stdin)
		scanner.Scan()
		sharedKey = scanner.Text()
	}

	if sharedKey == "" {
		return errors.New("shared key required")
	}

	if sa.Email == "" {
		return errors.New("email is required")
	}

	if len(sa.Audience) == 0 {
		return errors.New("aud is required")
	}

	if sa.Issuer == "" {
		return errors.New("iss is required")
	}
	encoder, err := jws.NewHS256Signer([]byte(sharedKey), sa.Issuer)
	if err != nil {
		return fmt.Errorf("bad shared key: %w", err)
	}
	raw, err := encoder.Marshal(sa)
	if err != nil {
		return fmt.Errorf("bad encode: %w", err)
	}
	fmt.Fprintf(os.Stdout, "%s", raw)
	return nil
}

func printHelp(fs *flag.FlagSet) {
	fmt.Fprintf(os.Stderr, strings.TrimSpace(help)+"\n\n", os.Args[0])
	fs.PrintDefaults()
}

const help = `
pomerium-cli generates a pomerium service account from a shared key.

Usage: %[1]s [flags] [base64'd shared secret setting]

For additional help see:

	https://www.pomerium.io
	https://jwt.io/

Flags:

`
