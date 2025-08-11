package handlers

import (
	"net/http"

	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/ui"
)

type SignInSuccessData struct {
	UserInfoData
	// TODO
}

func (data SignInSuccessData) ToJSON() map[string]any {
	m := data.UserInfoData.ToJSON()
	return m
}

func SignInSuccess(data SignInSuccessData) http.Handler {
	return httputil.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		return ui.ServePage(w, r, "SignInSuccess", "Sign In Successful", data.ToJSON())
	})
}
