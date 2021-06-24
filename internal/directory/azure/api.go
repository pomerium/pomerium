package azure

import "strings"

type (
	apiGetUserResponse struct {
		apiUser
	}
	apiGetUserMembersResponse struct {
		Context  string     `json:"@odata.context"`
		NextLink string     `json:"@odata.nextLink,omitempty"`
		Value    []apiGroup `json:"value"`
	}

	apiGroup struct {
		ID          string `json:"id"`
		DisplayName string `json:"displayName"`
	}
	apiUser struct {
		ID                string `json:"id"`
		DisplayName       string `json:"displayName"`
		Mail              string `json:"mail"`
		UserPrincipalName string `json:"userPrincipalName"`
	}
)

func (obj apiUser) getEmail() string {
	if obj.Mail != "" {
		return obj.Mail
	}

	// AD often doesn't have the email address returned, but we can parse it from the UPN

	// UPN looks like:
	// cdoxsey_pomerium.com#EXT#@cdoxseypomerium.onmicrosoft.com
	email := obj.UserPrincipalName
	if idx := strings.Index(email, "#EXT"); idx > 0 {
		email = email[:idx]
	}
	// find the last _ and replace it with @
	if idx := strings.LastIndex(email, "_"); idx > 0 {
		email = email[:idx] + "@" + email[idx+1:]
	}
	return email
}
