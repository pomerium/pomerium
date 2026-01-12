package hosted

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v3"
	"github.com/go-jose/go-jose/v3/jwt"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/codes"
	"golang.org/x/oauth2"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/identity/identity"
	"github.com/pomerium/pomerium/pkg/identity/oauth"
	"github.com/pomerium/pomerium/pkg/identity/oidc"
	pom_oidc "github.com/pomerium/pomerium/pkg/identity/oidc"
	"github.com/pomerium/pomerium/pkg/identity/oidc/internal"
	"github.com/pomerium/pomerium/pkg/telemetry/trace"
)

const (
	// Name identifies the Hosted Authenticate identity provider
	Name = "hosted"

	DefaultProviderURL = "https://authenticate.pomerium.app"
)

// Provider implements the Authenticator interface using the Hosted Authenticate service
// as an OIDC Provider.
type Provider struct {
	*pom_oidc.Provider

	providerURL string

	requestSigner         jose.Signer
	clientAssertionSigner jose.Signer

	pomeriumVersion string
}

// New instantiates a Provider.
func New(ctx context.Context, o *oauth.Options) (*Provider, error) {
	// Currently the JWT signing key is passed in using the ClientSecret field
	// in the oauth.Options. Copy it out of this field and clear the field as it
	// should not be sent to the identity provider.
	// TODO: refactor this to give the signing key its own dedicated field.
	keyBytes, err := base64.RawStdEncoding.DecodeString(o.ClientSecret)
	if err != nil {
		return nil, fmt.Errorf("invalid client secret: %w", err)
	}
	key := ed25519.PrivateKey(keyBytes)
	o2 := *o
	o2.ClientSecret = ""

	if len(key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("invalid Ed25519 private key")
	}

	jwk := jose.JSONWebKey{Key: key.Public()}
	requestSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: key},
		(&jose.SignerOptions{}).WithType("JWT").WithHeader("jwk", jwk),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize request JWT signer: %w", err)
	}
	clientAssertionSigner, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: key},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize client assertion JWT signer: %w", err)
	}
	p := &Provider{
		providerURL:           o.ProviderURL,
		requestSigner:         requestSigner,
		clientAssertionSigner: clientAssertionSigner,
		pomeriumVersion:       urlutil.VersionStr(),
	}

	genericOidc, err := pom_oidc.New(ctx, &o2, pom_oidc.WithGetExchangeOptions(p.getExchangeOptions))
	if err != nil {
		return nil, fmt.Errorf("%s: failed creating oidc provider: %w", Name, err)
	}
	p.Provider = genericOidc
	return p, nil
}

func (p *Provider) SignIn(w http.ResponseWriter, r *http.Request, state string) error {
	_, span := trace.Continue(r.Context(), "oidc: sign in")
	defer span.End()

	authCodeURL, err := p.authCodeURL(state)
	if err != nil {
		span.SetStatus(codes.Error, err.Error())
		return httputil.NewError(http.StatusInternalServerError, err)
	}

	httputil.Redirect(w, r, authCodeURL, http.StatusFound)
	return nil
}

// authCodeURL returns an auth code URL containing a signed JWT request object.
func (p *Provider) authCodeURL(state string) (string, error) {
	c, err := p.GetOauthConfig()
	if err != nil {
		return "", err
	}

	jwt, err := p.signRequestJWT(c, state)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	buf.WriteString(c.Endpoint.AuthURL)
	if strings.Contains(c.Endpoint.AuthURL, "?") {
		buf.WriteByte('&')
	} else {
		buf.WriteByte('?')
	}
	buf.WriteString(url.Values{"request": {jwt}}.Encode())
	return buf.String(), nil
}

// signRequestJWT returns a signed auth request object.
func (p *Provider) signRequestJWT(c *oauth2.Config, state string) (string, error) {
	claims := map[string]any{
		"response_type":    "code",
		"client_id":        c.ClientID,
		"redirect_uri":     c.RedirectURL,
		"scope":            strings.Join(c.Scopes, " "),
		"state":            state,
		"pomerium_version": p.pomeriumVersion,
	}
	for k, v := range p.AuthCodeOptions {
		claims[k] = v
	}

	// From the OIDC spec §6.1:
	//
	// If signed, the Request Object SHOULD contain the Claims iss (issuer)
	// and aud (audience) as members. The iss value SHOULD be the Client ID
	// of the RP, unless it was signed by a different party than the RP. The
	// aud value SHOULD be or include the OP's Issuer Identifier URL.
	claims["iss"] = c.ClientID
	claims["aud"] = p.providerURL

	now := time.Now()
	claims["iat"] = jwt.NewNumericDate(now)
	claims["exp"] = jwt.NewNumericDate(now.Add(5 * time.Minute))

	return jwt.Signed(p.requestSigner).Claims(claims).CompactSerialize()
}

const clientAssertionType = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

func (p *Provider) getExchangeOptions(ctx context.Context, oa *oauth2.Config) []oauth2.AuthCodeOption {
	jwt, err := p.signClientAssertionJWT(oa)
	if err != nil {
		log.Ctx(ctx).Error().Err(err).Msg("hosted.Provider: couldn't sign client assertion JWT")
		return nil
	}
	return []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("client_assertion_type", clientAssertionType),
		oauth2.SetAuthURLParam("client_assertion", jwt),
	}
}

func (p *Provider) Refresh(ctx context.Context, t *oauth2.Token, v identity.State) (*oauth2.Token, error) {
	_, span := trace.Continue(ctx, "oidc: refresh")
	defer span.End()

	oa, err := p.GetOauthConfig()
	if err != nil {
		return nil, err
	}

	clientAssertion, err := p.signClientAssertionJWT(oa)
	if err != nil {
		return nil, err
	}

	params := url.Values{
		"client_assertion_type": {clientAssertionType},
		"client_assertion":      {clientAssertion},
		"grant_type":            {"refresh_token"},
		"refresh_token":         {t.RefreshToken},
	}
	newToken, err := doTokenRequest(ctx, oa.Endpoint.TokenURL, params)
	if err != nil {
		return nil, err
	}

	idToken := oidc.GetRawIDToken(newToken)
	v.SetRawIDToken(idToken)
	if parsed, err := internal.VerifyIDToken(ctx, p, idToken); err == nil {
		parsed.Claims(v)
	}

	return newToken, nil
}

func (p *Provider) signClientAssertionJWT(oa *oauth2.Config) (string, error) {
	id, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	now := time.Now()

	claims := struct {
		jwt.Claims
		PomeriumVersion string `json:"pomerium_version"`
	}{
		Claims: jwt.Claims{
			Issuer:   oa.ClientID,
			Subject:  oa.ClientID,
			Audience: jwt.Audience{oa.Endpoint.TokenURL},
			ID:       id.String(),
			IssuedAt: jwt.NewNumericDate(now),
			Expiry:   jwt.NewNumericDate(now.Add(5 * time.Minute)),
		},
		PomeriumVersion: p.pomeriumVersion,
	}
	return jwt.Signed(p.clientAssertionSigner).Claims(claims).CompactSerialize()
}

// Name returns the provider name.
func (p *Provider) Name() string {
	return Name
}
