package authenticate

import (
	"context"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"

	"golang.org/x/oauth2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/identity"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	identitypb "github.com/pomerium/pomerium/pkg/grpc/identity"
)

var cookieChunker = httputil.NewCookieChunker()

func (a *Authenticate) buildIdentityProfile(
	r *http.Request,
	claims identity.SessionClaims,
	oauthToken *oauth2.Token,
) (*identitypb.Profile, error) {
	idpID := r.FormValue(urlutil.QueryIdentityProviderID)

	rawIDToken := []byte(claims.RawIDToken)
	rawOAuthToken, err := json.Marshal(oauthToken)
	if err != nil {
		return nil, fmt.Errorf("authenticate: error marshaling oauth token: %w", err)
	}
	rawClaims, err := structpb.NewStruct(claims.Claims)
	if err != nil {
		return nil, fmt.Errorf("authenticate: error creating claims struct: %w", err)
	}

	return &identitypb.Profile{
		ProviderId: idpID,
		IdToken:    rawIDToken,
		OauthToken: rawOAuthToken,
		Claims:     rawClaims,
	}, nil
}

func (a *Authenticate) loadIdentityProfile(r *http.Request, aead cipher.AEAD) (*identitypb.Profile, error) {
	cookie, err := cookieChunker.LoadCookie(r, urlutil.QueryIdentityProfile)
	if err != nil {
		return nil, fmt.Errorf("authenticate: error loading identity profile cookie: %w", err)
	}

	encrypted, err := base64.RawURLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return nil, fmt.Errorf("authenticate: error decoding identity profile cookie: %w", err)
	}

	decrypted, err := cryptutil.Decrypt(aead, encrypted, nil)
	if err != nil {
		return nil, fmt.Errorf("authenticate: error decrypting identity profile cookie: %w", err)
	}

	var profile identitypb.Profile
	err = protojson.Unmarshal(decrypted, &profile)
	if err != nil {
		return nil, fmt.Errorf("authenticate: error unmarshaling identity profile cookie: %w", err)
	}
	return &profile, nil
}

func (a *Authenticate) storeIdentityProfile(w http.ResponseWriter, aead cipher.AEAD, profile *identitypb.Profile) error {
	options := a.options.Load()

	decrypted, err := protojson.Marshal(profile)
	if err != nil {
		// this shouldn't happen
		panic(fmt.Errorf("error marshaling message: %w", err))
	}
	encrypted := cryptutil.Encrypt(aead, decrypted, nil)
	cookie := options.NewCookie()
	cookie.Name = urlutil.QueryIdentityProfile
	cookie.Value = base64.RawURLEncoding.EncodeToString(encrypted)
	cookie.Path = "/"
	return cookieChunker.SetCookie(w, cookie)
}

func (a *Authenticate) validateIdentityProfile(ctx context.Context, profile *identitypb.Profile) error {
	authenticator, err := a.cfg.getIdentityProvider(a.options.Load(), profile.GetProviderId())
	if err != nil {
		return err
	}

	oauthToken := new(oauth2.Token)
	err = json.Unmarshal(profile.GetOauthToken(), oauthToken)
	if err != nil {
		return fmt.Errorf("invalid oauth token in profile: %w", err)
	}

	if !oauthToken.Valid() {
		return fmt.Errorf("invalid oauth token in profile")
	}

	var claims identity.SessionClaims
	err = authenticator.UpdateUserInfo(ctx, oauthToken, &claims)
	if err != nil {
		return fmt.Errorf("error updating user info from oauth token: %w", err)
	}

	return nil
}
