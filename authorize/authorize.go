// Package authorize is a pomerium service that is responsible for determining
// if a given request should be authorized (AuthZ).
package authorize

//go:generate ../scripts/protoc -I ../internal/grpc/authorize/ --go_out=plugins=grpc:../internal/grpc/authorize/ ../internal/grpc/authorize/authorize.proto

import (
	"context"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/ioutil"
	"sync/atomic"

	"github.com/pomerium/pomerium/authorize/evaluator"
	"github.com/pomerium/pomerium/authorize/evaluator/opa"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/cryptutil"
	"github.com/pomerium/pomerium/internal/encoding"
	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/frontend"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/telemetry/metrics"
	"github.com/pomerium/pomerium/internal/telemetry/trace"

	"gopkg.in/square/go-jose.v2"
)

type atomicOptions struct {
	value atomic.Value
}

func (a *atomicOptions) Load() config.Options {
	return a.value.Load().(config.Options)
}

func (a *atomicOptions) Store(options config.Options) {
	a.value.Store(options)
}

type atomicMarshalUnmarshaler struct {
	value atomic.Value
}

func (a *atomicMarshalUnmarshaler) Load() encoding.MarshalUnmarshaler {
	return a.value.Load().(encoding.MarshalUnmarshaler)
}

func (a *atomicMarshalUnmarshaler) Store(encoder encoding.MarshalUnmarshaler) {
	a.value.Store(encoder)
}

// Authorize struct holds
type Authorize struct {
	pe evaluator.Evaluator

	currentOptions atomicOptions
	currentEncoder atomicMarshalUnmarshaler
	templates      *template.Template
}

// New validates and creates a new Authorize service from a set of config options.
func New(opts config.Options) (*Authorize, error) {
	if err := validateOptions(opts); err != nil {
		return nil, fmt.Errorf("authorize: bad options: %w", err)
	}
	a := Authorize{
		templates: template.Must(frontend.NewTemplates()),
	}

	var host string
	if opts.AuthenticateURL != nil {
		host = opts.AuthenticateURL.Host
	}
	encoder, err := jws.NewHS256Signer([]byte(opts.SharedKey), host)
	if err != nil {
		return nil, err
	}
	a.currentEncoder.Store(encoder)

	a.currentOptions.Store(config.Options{})
	err = a.UpdateOptions(opts)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

func validateOptions(o config.Options) error {
	if _, err := cryptutil.NewAEADCipherFromBase64(o.SharedKey); err != nil {
		return fmt.Errorf("bad shared_secret: %w", err)
	}
	return nil
}

// newPolicyEvaluator returns an policy evaluator.
func newPolicyEvaluator(opts *config.Options) (evaluator.Evaluator, error) {
	metrics.AddPolicyCountCallback("authorize", func() int64 {
		return int64(len(opts.Policies))
	})
	ctx := context.Background()
	ctx, span := trace.StartSpan(ctx, "authorize.newPolicyEvaluator")
	defer span.End()
	var jwk jose.JSONWebKey
	if opts.SigningKey == "" {
		key, err := cryptutil.NewSigningKey()
		if err != nil {
			return nil, fmt.Errorf("authorize: couldn't generate signing key: %w", err)
		}
		jwk.Key = key
		pubKeyBytes, err := cryptutil.EncodePublicKey(&key.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("authorize: encode public key: %w", err)
		}
		log.Info().Interface("PublicKey", pubKeyBytes).Msg("authorize: ecdsa public key")
	} else {
		decodedCert, err := base64.StdEncoding.DecodeString(opts.SigningKey)
		if err != nil {
			return nil, fmt.Errorf("authorize: failed to decode certificate cert %v: %w", decodedCert, err)
		}
		keyBytes, err := cryptutil.DecodePrivateKey((decodedCert))
		if err != nil {
			return nil, fmt.Errorf("authorize: couldn't generate signing key: %w", err)
		}
		jwk.Key = keyBytes
	}

	var clientCA string
	if opts.ClientCA != "" {
		bs, err := base64.StdEncoding.DecodeString(opts.ClientCA)
		if err != nil {
			return nil, fmt.Errorf("authorize: invalid client ca: %w", err)
		}
		clientCA = string(bs)
	} else if opts.ClientCAFile != "" {
		bs, err := ioutil.ReadFile(opts.ClientCAFile)
		if err != nil {
			return nil, fmt.Errorf("authorize: invalid client ca file: %w", err)
		}
		clientCA = string(bs)
	}

	data := map[string]interface{}{
		"shared_key":       opts.SharedKey,
		"route_policies":   opts.Policies,
		"admins":           opts.Administrators,
		"signing_key":      jwk,
		"authenticate_url": opts.AuthenticateURLString,
		"client_ca":        clientCA,
	}

	return opa.New(ctx, &opa.Options{Data: data})
}

// UpdateOptions implements the OptionsUpdater interface and updates internal
// structures based on config.Options
func (a *Authorize) UpdateOptions(opts config.Options) error {
	if a == nil {
		return nil
	}

	log.Info().Str("checksum", fmt.Sprintf("%x", opts.Checksum())).Msg("authorize: updating options")
	a.currentOptions.Store(opts)

	var err error
	if a.pe, err = newPolicyEvaluator(&opts); err != nil {
		return err
	}
	return nil
}
