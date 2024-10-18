package authenticateflow

import (
	"context"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"golang.org/x/oauth2"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	identitypb "github.com/pomerium/pomerium/pkg/grpc/identity"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/identity"
	"github.com/pomerium/pomerium/pkg/identity/manager"
)

// An "identity profile" is an alternative to a session, used in the stateless
// authenticate flow. An identity profile contains an IdP ID (to distinguish
// between different IdP's or between different clients of the same IdP), a
// user ID token, and an OAuth2 token.

var cookieChunker = httputil.NewCookieChunker()

// buildIdentityProfile populates an identity profile.
func buildIdentityProfile(
	idpID string,
	claims identity.SessionClaims,
	oauthToken *oauth2.Token,
) (*identitypb.Profile, error) {
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

// loadIdentityProfile loads an identity profile from a chunked set of cookies.
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

// storeIdentityProfile writes the identity profile to a chunked set of cookies.
func storeIdentityProfile(
	w http.ResponseWriter,
	cookie *http.Cookie,
	aead cipher.AEAD,
	profile *identitypb.Profile,
) error {
	decrypted, err := protojson.Marshal(profile)
	if err != nil {
		// this shouldn't happen
		panic(fmt.Errorf("error marshaling message: %w", err))
	}
	encrypted := cryptutil.Encrypt(aead, decrypted, nil)
	cookie.Name = urlutil.QueryIdentityProfile
	cookie.Value = base64.RawURLEncoding.EncodeToString(encrypted)
	cookie.Path = "/"
	return cookieChunker.SetCookie(w, cookie)
}

// validateIdentityProfile checks expirations timestamps for the ID token and
// OAuth2 token, and makes a user info request to the IdP in order to determine
// whether the OAuth2 token is still valid.
func validateIdentityProfile(
	ctx context.Context,
	authenticator identity.Authenticator,
	profile *identitypb.Profile,
) error {
	oauthToken := new(oauth2.Token)
	err := json.Unmarshal(profile.GetOauthToken(), oauthToken)
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

func newSessionStateFromProfile(p *identitypb.Profile, sessionDuration time.Duration) *sessions.State {
	claims := p.GetClaims().AsMap()

	ss := sessions.NewState(p.GetProviderId(), sessionDuration)

	// set the subject
	if v, ok := claims["sub"]; ok {
		ss.Subject = fmt.Sprint(v)
	} else if v, ok := claims["user"]; ok {
		ss.Subject = fmt.Sprint(v)
	}

	// set the oid
	if v, ok := claims["oid"]; ok {
		ss.OID = fmt.Sprint(v)
	}

	return ss
}

func populateSessionFromProfile(s *session.Session, p *identitypb.Profile, ss *sessions.State, cookieExpire time.Duration) {
	claims := p.GetClaims().AsMap()
	oauthToken := new(oauth2.Token)
	_ = json.Unmarshal(p.GetOauthToken(), oauthToken)

	s.UserId = ss.UserID()
	issuedAt := timeNow()
	s.IssuedAt = timestamppb.New(issuedAt)
	s.AccessedAt = timestamppb.New(issuedAt)
	s.ExpiresAt = timestamppb.New(issuedAt.Add(cookieExpire))
	s.OauthToken = manager.ToOAuthToken(oauthToken)
	s.SetRawIDToken(string(p.GetIdToken()))
	if s.Claims == nil {
		s.Claims = make(map[string]*structpb.ListValue)
	}
	for k, vs := range identity.Claims(claims).Flatten().ToPB() {
		s.Claims[k] = vs
	}
}
