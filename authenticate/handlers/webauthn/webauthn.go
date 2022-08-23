// Package webauthn contains handlers for the WebAuthn flow in authenticate.
package webauthn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/encoding/jws"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/sessions"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/cryptutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/device"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/webauthnutil"
	"github.com/pomerium/pomerium/ui"
	"github.com/pomerium/webauthn"
)

const maxAuthenticateResponses = 5

var (
	errMissingDeviceCredentialID = httputil.NewError(http.StatusBadRequest, errors.New(
		urlutil.QueryDeviceCredentialID+" is a required parameter"))
	errMissingDeviceType = httputil.NewError(http.StatusBadRequest, errors.New(
		urlutil.QueryDeviceType+" is a required parameter"))
	errMissingRedirectURI = httputil.NewError(http.StatusBadRequest, errors.New(
		urlutil.QueryRedirectURI+" is a required parameter"))
	errInvalidDeviceCredential = httputil.NewError(http.StatusBadRequest, errors.New(
		"invalid device credential"))
)

// State is the state needed by the Handler to handle requests.
type State struct {
	AuthenticateURL         *url.URL
	InternalAuthenticateURL *url.URL
	Client                  databroker.DataBrokerServiceClient
	PomeriumDomains         []string
	RelyingParty            *webauthn.RelyingParty
	Session                 *session.Session
	SessionState            *sessions.State
	SessionStore            sessions.SessionStore
	SharedKey               []byte
	BrandingOptions         httputil.BrandingOptions
}

// A StateProvider provides state for the handler.
type StateProvider = func(context.Context) (*State, error)

// Handler is the WebAuthn device handler.
type Handler struct {
	getState StateProvider
}

// New creates a new Handler.
func New(getState StateProvider) *Handler {
	return &Handler{
		getState: getState,
	}
}

// GetOptions returns the creation and request options for WebAuthn.
func (h *Handler) GetOptions(ctx context.Context) (
	creationOptions *webauthn.PublicKeyCredentialCreationOptions,
	requestOptions *webauthn.PublicKeyCredentialRequestOptions,
	err error,
) {
	state, err := h.getState(ctx)
	if err != nil {
		return nil, nil, err
	}

	return h.getOptions(ctx, state, webauthnutil.DefaultDeviceType)
}

// ServeHTTP serves the HTTP handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	httputil.HandlerFunc(h.handle).ServeHTTP(w, r)
}

func (h *Handler) getOptions(ctx context.Context, state *State, deviceTypeParam string) (
	creationOptions *webauthn.PublicKeyCredentialCreationOptions,
	requestOptions *webauthn.PublicKeyCredentialRequestOptions,
	err error,
) {
	// get the user information
	u, err := user.Get(ctx, state.Client, state.Session.GetUserId())
	if err != nil {
		return nil, nil, err
	}

	// get the device credentials
	knownDeviceCredentials, err := getKnownDeviceCredentials(ctx, state.Client, u.GetDeviceCredentialIds()...)
	if err != nil {
		return nil, nil, err
	}

	// get the stored device type
	deviceType := webauthnutil.GetDeviceType(ctx, state.Client, deviceTypeParam)

	creationOptions = webauthnutil.GenerateCreationOptions(state.SharedKey, deviceType, u)
	requestOptions = webauthnutil.GenerateRequestOptions(state.SharedKey, deviceType, knownDeviceCredentials)
	return creationOptions, requestOptions, nil
}

func (h *Handler) handle(w http.ResponseWriter, r *http.Request) error {
	s, err := h.getState(r.Context())
	if err != nil {
		return err
	}

	err = middleware.ValidateRequestURL(
		urlutil.GetExternalRequest(s.InternalAuthenticateURL, s.AuthenticateURL, r),
		s.SharedKey,
	)
	if err != nil {
		return err
	}

	switch {
	case r.Method == "GET":
		return h.handleView(w, r, s)
	case r.FormValue("action") == "authenticate":
		return h.handleAuthenticate(w, r, s)
	case r.FormValue("action") == "register":
		return h.handleRegister(w, r, s)
	case r.FormValue("action") == "unregister":
		return h.handleUnregister(w, r, s)
	}

	return httputil.NewError(http.StatusNotFound, errors.New(http.StatusText(http.StatusNotFound)))
}

func (h *Handler) handleAuthenticate(w http.ResponseWriter, r *http.Request, state *State) error {
	ctx := r.Context()

	deviceTypeParam := r.FormValue(urlutil.QueryDeviceType)
	if deviceTypeParam == "" {
		return errMissingDeviceType
	}

	redirectURIParam := r.FormValue(urlutil.QueryRedirectURI)
	if redirectURIParam == "" {
		return errMissingRedirectURI
	}

	responseParam := r.FormValue("authenticate_response")
	var credential webauthn.PublicKeyAssertionCredential
	err := json.Unmarshal([]byte(responseParam), &credential)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, errors.New("invalid authenticate response"))
	}
	credentialJSON, err := json.Marshal(credential)
	if err != nil {
		return err
	}
	// Set the UserHandle which won't typically be filled in by the client
	credential.Response.UserHandle = webauthnutil.GetUserEntityID(state.Session.GetUserId())

	// get the user information
	u, err := user.Get(ctx, state.Client, state.Session.GetUserId())
	if err != nil {
		return fmt.Errorf("error retrieving user record: %w", err)
	}

	// get the stored device type
	deviceType := webauthnutil.GetDeviceType(ctx, state.Client, deviceTypeParam)

	// get the device credentials
	knownDeviceCredentials, err := getKnownDeviceCredentials(ctx, state.Client, u.GetDeviceCredentialIds()...)
	if err != nil {
		return fmt.Errorf("error retrieving webauthn known device credentials: %w", err)
	}

	requestOptions, err := webauthnutil.GetRequestOptionsForCredential(
		state.SharedKey,
		deviceType,
		knownDeviceCredentials,
		&credential,
	)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, fmt.Errorf("invalid register options: %w", err))
	}

	serverCredential, err := state.RelyingParty.VerifyAuthenticationCeremony(
		ctx,
		requestOptions,
		&credential,
	)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, fmt.Errorf("error verifying registration: %w", err))
	}

	// store the authenticate response
	for _, deviceCredential := range knownDeviceCredentials {
		webauthnCredential := deviceCredential.GetWebauthn()
		if webauthnCredential == nil {
			continue
		}

		if !bytes.Equal(webauthnCredential.Id, serverCredential.ID) {
			continue
		}

		// add the response to the list and cap it, removing the oldest responses
		webauthnCredential.AuthenticateResponse = append(webauthnCredential.AuthenticateResponse, credentialJSON)
		for len(webauthnCredential.AuthenticateResponse) > maxAuthenticateResponses {
			webauthnCredential.AuthenticateResponse = webauthnCredential.AuthenticateResponse[1:]
		}

		// store the updated device credential
		err = device.PutCredential(ctx, state.Client, deviceCredential)
		if err != nil {
			return err
		}
	}

	// update the session
	state.Session.DeviceCredentials = append(state.Session.DeviceCredentials, &session.Session_DeviceCredential{
		TypeId: deviceType.GetId(),
		Credential: &session.Session_DeviceCredential_Id{
			Id: webauthnutil.GetDeviceCredentialID(serverCredential.ID),
		},
	})
	return h.saveSessionAndRedirect(w, r, state, redirectURIParam)
}

func (h *Handler) handleRegister(w http.ResponseWriter, r *http.Request, state *State) error {
	ctx := r.Context()

	deviceTypeParam := r.FormValue(urlutil.QueryDeviceType)
	if deviceTypeParam == "" {
		return errMissingDeviceType
	}

	redirectURIParam := r.FormValue(urlutil.QueryRedirectURI)
	if redirectURIParam == "" {
		return errMissingRedirectURI
	}

	responseParam := r.FormValue("register_response")
	var credential webauthn.PublicKeyCreationCredential
	err := json.Unmarshal([]byte(responseParam), &credential)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, errors.New("invalid register response"))
	}
	credentialJSON, err := json.Marshal(credential)
	if err != nil {
		return err
	}

	// get the user information
	u, err := user.Get(ctx, state.Client, state.Session.GetUserId())
	if err != nil {
		return fmt.Errorf("error retrieving user record: %w", err)
	}

	// get the stored device type
	deviceType := webauthnutil.GetDeviceType(ctx, state.Client, deviceTypeParam)

	creationOptions, err := webauthnutil.GetCreationOptionsForCredential(
		state.SharedKey,
		deviceType,
		u,
		&credential,
	)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, fmt.Errorf("invalid register options: %w", err))
	}
	creationOptionsJSON, err := json.Marshal(creationOptions)
	if err != nil {
		return err
	}

	serverCredential, err := state.RelyingParty.VerifyRegistrationCeremony(
		ctx,
		creationOptions,
		&credential,
	)
	if err != nil {
		return httputil.NewError(http.StatusBadRequest, fmt.Errorf("error verifying registration: %w", err))
	}

	deviceCredentialID := webauthnutil.GetDeviceCredentialID(serverCredential.ID)

	deviceEnrollment, err := getOrCreateDeviceEnrollment(ctx, r, state, deviceType.GetId(), deviceCredentialID, u)
	if err != nil {
		return err
	}

	// save the credential
	deviceCredential := &device.Credential{
		Id:           deviceCredentialID,
		TypeId:       deviceType.GetId(),
		EnrollmentId: deviceEnrollment.GetId(),
		UserId:       u.GetId(),
		Specifier: &device.Credential_Webauthn{
			Webauthn: &device.Credential_WebAuthn{
				Id:        serverCredential.ID,
				PublicKey: serverCredential.PublicKey,

				RegisterOptions:  creationOptionsJSON,
				RegisterResponse: credentialJSON,
			},
		},
	}
	err = device.PutCredential(ctx, state.Client, deviceCredential)
	if err != nil {
		return err
	}

	// save the user
	u.DeviceCredentialIds = append(u.DeviceCredentialIds, deviceCredential.GetId())
	_, err = databroker.Put(ctx, state.Client, u)
	if err != nil {
		return err
	}

	// update the session
	state.Session.DeviceCredentials = append(state.Session.DeviceCredentials, &session.Session_DeviceCredential{
		TypeId: deviceType.GetId(),
		Credential: &session.Session_DeviceCredential_Id{
			Id: webauthnutil.GetDeviceCredentialID(serverCredential.ID),
		},
	})

	return h.saveSessionAndRedirect(w, r, state, redirectURIParam)
}

func (h *Handler) handleUnregister(w http.ResponseWriter, r *http.Request, state *State) error {
	ctx := r.Context()

	// get the user information
	u, err := user.Get(ctx, state.Client, state.Session.GetUserId())
	if err != nil {
		return err
	}

	deviceCredentialID := r.FormValue(urlutil.QueryDeviceCredentialID)
	if deviceCredentialID == "" {
		return errMissingDeviceCredentialID
	}

	// ensure we only allow removing a device credential the user owns
	if !containsString(u.GetDeviceCredentialIds(), deviceCredentialID) {
		return errInvalidDeviceCredential
	}

	// delete the credential
	deviceCredential, err := device.DeleteCredential(ctx, state.Client, deviceCredentialID)
	if err != nil {
		return err
	}

	// delete the corresponding enrollment
	_, err = device.DeleteEnrollment(ctx, state.Client, deviceCredential.GetEnrollmentId())
	if err != nil {
		return err
	}

	// remove the credential from the user
	u.DeviceCredentialIds = removeString(u.DeviceCredentialIds, deviceCredentialID)
	_, err = databroker.Put(ctx, state.Client, u)
	if err != nil {
		return err
	}

	// remove the credential from the session
	state.Session.DeviceCredentials = removeSessionDeviceCredential(state.Session.DeviceCredentials, deviceCredentialID)
	return h.saveSessionAndRedirect(w, r, state, urlutil.GetAbsoluteURL(r).ResolveReference(&url.URL{
		Path: "/.pomerium",
	}).String())
}

func (h *Handler) handleView(w http.ResponseWriter, r *http.Request, state *State) error {
	ctx := r.Context()

	deviceTypeParam := r.FormValue(urlutil.QueryDeviceType)
	if deviceTypeParam == "" {
		return errMissingDeviceType
	}

	creationOptions, requestOptions, err := h.getOptions(ctx, state, deviceTypeParam)
	if err != nil {
		return err
	}

	m := map[string]interface{}{
		"creationOptions": creationOptions,
		"requestOptions":  requestOptions,
		"selfUrl":         r.URL.String(),
	}
	httputil.AddBrandingOptionsToMap(m, state.BrandingOptions)
	return ui.ServePage(w, r, "WebAuthnRegistration", m)
}

func (h *Handler) saveSessionAndRedirect(w http.ResponseWriter, r *http.Request, state *State, rawRedirectURI string) error {
	// save the session to the databroker
	res, err := session.Put(r.Context(), state.Client, state.Session)
	if err != nil {
		return err
	}

	// add databroker versions to the session cookie and save
	state.SessionState.DatabrokerServerVersion = res.GetServerVersion()
	state.SessionState.DatabrokerRecordVersion = res.GetRecord().GetVersion()
	err = state.SessionStore.SaveSession(w, r, state.SessionState)
	if err != nil {
		return err
	}

	// if the redirect URL is for a URL we don't control, just do a plain redirect
	if !isURLForPomerium(state.PomeriumDomains, rawRedirectURI) {
		httputil.Redirect(w, r, rawRedirectURI, http.StatusFound)
		return nil
	}

	// sign+encrypt the session JWT
	encoder, err := jws.NewHS256Signer(state.SharedKey)
	if err != nil {
		return err
	}

	signedJWT, err := encoder.Marshal(state.SessionState)
	if err != nil {
		return err
	}

	cipher, err := cryptutil.NewAEADCipher(state.SharedKey)
	if err != nil {
		return err
	}

	encryptedJWT := cryptutil.Encrypt(cipher, signedJWT, nil)
	encodedJWT := base64.URLEncoding.EncodeToString(encryptedJWT)

	// redirect to the proxy callback URL with the session
	callbackURL, err := urlutil.GetCallbackURLForRedirectURI(r, encodedJWT, rawRedirectURI)
	if err != nil {
		return err
	}

	signedCallbackURL := urlutil.NewSignedURL(state.SharedKey, callbackURL)
	httputil.Redirect(w, r, signedCallbackURL.String(), http.StatusFound)
	return nil
}

func getKnownDeviceCredentials(
	ctx context.Context,
	client databroker.DataBrokerServiceClient,
	deviceCredentialIDs ...string,
) ([]*device.Credential, error) {
	var knownDeviceCredentials []*device.Credential
	for _, deviceCredentialID := range deviceCredentialIDs {
		deviceCredential, err := device.GetCredential(ctx, client, deviceCredentialID)
		if status.Code(err) == codes.NotFound {
			// ignore missing devices
			continue
		} else if err != nil {
			return nil, httputil.NewError(http.StatusInternalServerError,
				fmt.Errorf("error retrieving device credential: %w", err))
		}
		knownDeviceCredentials = append(knownDeviceCredentials, deviceCredential)
	}
	return knownDeviceCredentials, nil
}

func getOrCreateDeviceEnrollment(
	ctx context.Context,
	r *http.Request,
	state *State,
	deviceTypeID string,
	deviceCredentialID string,
	u *user.User,
) (*device.Enrollment, error) {
	var deviceEnrollment *device.Enrollment

	enrollmentTokenParam := r.FormValue(urlutil.QueryEnrollmentToken)
	if enrollmentTokenParam == "" {
		// create a new enrollment
		deviceEnrollment = &device.Enrollment{
			Id:     uuid.New().String(),
			TypeId: deviceTypeID,
			UserId: u.GetId(),
		}
	} else {
		// use an existing enrollment
		deviceEnrollmentID, err := webauthnutil.ParseAndVerifyEnrollmentToken(state.SharedKey, enrollmentTokenParam)
		if err != nil {
			return nil, httputil.NewError(http.StatusBadRequest, fmt.Errorf("invalid enrollment token: %w", err))
		}

		deviceEnrollment, err = device.GetEnrollment(ctx, state.Client, deviceEnrollmentID)
		if err != nil {
			return nil, err
		}

		if deviceEnrollment.GetTypeId() != deviceTypeID {
			return nil, httputil.NewError(http.StatusForbidden, fmt.Errorf("invalid enrollment token: wrong device type"))
		}

		if deviceEnrollment.GetUserId() != u.GetId() {
			return nil, httputil.NewError(http.StatusForbidden, fmt.Errorf("invalid enrollment token: wrong user id"))
		}

		if deviceEnrollment.GetEnrolledAt().IsValid() {
			return nil, httputil.NewError(http.StatusForbidden, fmt.Errorf("invalid enrollment token: already used for existing credential"))
		}
	}

	deviceEnrollment.CredentialId = deviceCredentialID
	deviceEnrollment.EnrolledAt = timestamppb.Now()
	deviceEnrollment.UserAgent = r.UserAgent()
	deviceEnrollment.IpAddress = httputil.GetClientIPAddress(r)

	err := device.PutEnrollment(ctx, state.Client, deviceEnrollment)
	if err != nil {
		return nil, err
	}
	return deviceEnrollment, nil
}

func isURLForPomerium(pomeriumDomains []string, rawURI string) bool {
	uri, err := urlutil.ParseAndValidateURL(rawURI)
	if err != nil {
		return false
	}

	for _, domain := range pomeriumDomains {
		if urlutil.StripPort(domain) == urlutil.StripPort(uri.Host) {
			return true
		}
	}

	return false
}
