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
	"github.com/pomerium/pomerium/internal/log"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	identitypb "github.com/pomerium/pomerium/pkg/grpc/identity"
)

var cookieChunker = httputil.NewCookieChunker()

func (a *Authenticate) buildIdentityProfile(
	ctx context.Context,
	r *http.Request,
	_ *sessions.State,
	claims identity.SessionClaims,
	oauthToken *oauth2.Token,
) (*identitypb.Profile, error) {
	options := a.options.Load()
	idpID := r.FormValue(urlutil.QueryIdentityProviderID)

	authenticator, err := a.cfg.getIdentityProvider(options, idpID)
	if err != nil {
		return nil, fmt.Errorf("authenticate: error getting identity provider authenticator: %w", err)
	}

	err = authenticator.UpdateUserInfo(ctx, oauthToken, &claims)
	if err != nil {
		return nil, fmt.Errorf("authenticate: error retrieving user info: %w", err)
	}

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

func loadIdentityProfile(r *http.Request, aead cipher.AEAD) (*identitypb.Profile, error) {
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

func storeIdentityProfile(w http.ResponseWriter, aead cipher.AEAD, profile *identitypb.Profile) {
	decrypted, err := protojson.Marshal(profile)
	if err != nil {
		// this shouldn't happen
		panic(fmt.Errorf("error marshaling message: %w", err))
	}
	encrypted := cryptutil.Encrypt(aead, decrypted, nil)
	err = cookieChunker.SetCookie(w, &http.Cookie{
		Name:  urlutil.QueryIdentityProfile,
		Value: base64.RawURLEncoding.EncodeToString(encrypted),
		Path:  "/",
	})
	log.Error(context.Background()).Err(err).Send()
}
