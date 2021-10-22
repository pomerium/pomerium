// Package webauthn contains handlers for the WebAuthn flow in authenticate.
package webauthn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net"
	"net/http"

	"github.com/google/uuid"
	"github.com/pomerium/csrf"
	"github.com/pomerium/webauthn"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/pomerium/pomerium/internal/frontend"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/middleware"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/grpc/databroker"
	"github.com/pomerium/pomerium/pkg/grpc/device"
	"github.com/pomerium/pomerium/pkg/grpc/session"
	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/pomerium/pkg/webauthnutil"
)

const maxAuthenticateResponses = 5

var (
	errMissingDeviceType  = httputil.NewError(http.StatusBadRequest, errors.New("device_type is a required parameter"))
	errMissingRedirectURI = httputil.NewError(http.StatusBadRequest, errors.New("pomerium_redirect_uri is a required parameter"))
)

// State is the state needed by the Handler to handle requests.
type State struct {
	SharedKey    []byte
	Client       databroker.DataBrokerServiceClient
	Session      *session.Session
	RelyingParty *webauthn.RelyingParty
}

// A StateProvider provides state for the handler.
type StateProvider = func(context.Context) (*State, error)

// Handler is the WebAuthn device handler.
type Handler struct {
	getState  StateProvider
	templates *template.Template
}

// New creates a new Handler.
func New(getState StateProvider) *Handler {
	return &Handler{
		getState:  getState,
		templates: template.Must(frontend.NewTemplates()),
	}
}

// ServeHTTP serves the HTTP handler.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	httputil.HandlerFunc(h.handle).ServeHTTP(w, r)
}

func (h *Handler) handle(w http.ResponseWriter, r *http.Request) error {
	s, err := h.getState(r.Context())
	if err != nil {
		return err
	}

	err = middleware.ValidateRequestURL(r, s.SharedKey)
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
	deviceType, err := webauthnutil.GetDeviceType(ctx, state.Client, deviceTypeParam)
	if err != nil {
		return fmt.Errorf("error retrieving webauthn device type: %w", err)
	}

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

	// save the session
	state.Session.DeviceCredentials = append(state.Session.DeviceCredentials, &session.Session_DeviceCredential{
		TypeId: deviceType.GetId(),
		Credential: &session.Session_DeviceCredential_Id{
			Id: webauthnutil.GetDeviceCredentialID(serverCredential.ID),
		},
	})
	_, err = session.Put(ctx, state.Client, state.Session)
	if err != nil {
		return err
	}

	// redirect
	httputil.Redirect(w, r, redirectURIParam, http.StatusFound)
	return nil
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
	deviceType, err := webauthnutil.GetDeviceType(ctx, state.Client, deviceTypeParam)
	if err != nil {
		return fmt.Errorf("error retrieving webauthn device type: %w", err)
	}

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

	deviceEnrollment, err := getOrCreateDeviceEnrollment(ctx, r, state, u)
	if err != nil {
		return err
	}

	// save the credential
	deviceCredential := &device.Credential{
		Id:           webauthnutil.GetDeviceCredentialID(serverCredential.ID),
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
	_, err = user.Put(ctx, state.Client, u)
	if err != nil {
		return err
	}

	// save the session
	state.Session.DeviceCredentials = append(state.Session.DeviceCredentials, &session.Session_DeviceCredential{
		TypeId: deviceType.GetId(),
		Credential: &session.Session_DeviceCredential_Id{
			Id: webauthnutil.GetDeviceCredentialID(serverCredential.ID),
		},
	})
	_, err = session.Put(ctx, state.Client, state.Session)
	if err != nil {
		return err
	}

	// redirect
	httputil.Redirect(w, r, redirectURIParam, http.StatusFound)
	return nil
}

func (h *Handler) handleView(w http.ResponseWriter, r *http.Request, state *State) error {
	ctx := r.Context()

	deviceTypeParam := r.FormValue(urlutil.QueryDeviceType)
	if deviceTypeParam == "" {
		return errMissingDeviceType
	}

	// get the user information
	u, err := user.Get(ctx, state.Client, state.Session.GetUserId())
	if err != nil {
		return err
	}

	// get the device credentials
	knownDeviceCredentials, err := getKnownDeviceCredentials(ctx, state.Client, u.GetDeviceCredentialIds()...)
	if err != nil {
		return err
	}

	// get the stored device type
	deviceType, err := webauthnutil.GetDeviceType(ctx, state.Client, deviceTypeParam)
	if err != nil {
		return err
	}

	creationOptions := webauthnutil.GenerateCreationOptions(state.SharedKey, deviceType, u)
	requestOptions := webauthnutil.GenerateRequestOptions(state.SharedKey, deviceType, knownDeviceCredentials)

	var buf bytes.Buffer
	err = h.templates.ExecuteTemplate(&buf, "webauthn.html", map[string]interface{}{
		"csrfField": csrf.TemplateField(r),
		"Data": map[string]interface{}{
			"creationOptions": creationOptions,
			"requestOptions":  requestOptions,
		},
		"SelfURL": r.URL.String(),
	})
	if err != nil {
		return err
	}

	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusOK)
	_, err = io.Copy(w, &buf)
	return err
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
	u *user.User,
) (*device.Enrollment, error) {
	var deviceEnrollment *device.Enrollment

	enrollmentTokenParam := r.FormValue(urlutil.QueryEnrollmentToken)
	if enrollmentTokenParam == "" {
		// create a new enrollment
		deviceEnrollment = &device.Enrollment{
			Id:     uuid.New().String(),
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

		if deviceEnrollment.GetUserId() != u.GetId() {
			return nil, httputil.NewError(http.StatusForbidden, fmt.Errorf("invalid enrollment token: wrong user id"))
		}

		if deviceEnrollment.GetEnrolledAt().IsValid() {
			return nil, httputil.NewError(http.StatusForbidden, fmt.Errorf("invalid enrollment token: already used for existing credential"))
		}
	}

	deviceEnrollment.EnrolledAt = timestamppb.Now()
	deviceEnrollment.UserAgent = r.UserAgent()
	if ip, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		deviceEnrollment.IpAddress = ip
	}

	err := device.PutEnrollment(ctx, state.Client, deviceEnrollment)
	if err != nil {
		return nil, err
	}
	return deviceEnrollment, nil
}
