package management

import (
	"encoding/json"
	"fmt"
)

type Branding struct {
	// Change password page settings
	Colors *BrandingColors `json:"colors,omitempty"`

	// URL for the favicon. Must use HTTPS.
	FaviconURL *string `json:"favicon_url,omitempty"`

	// URL for the logo. Must use HTTPS.
	LogoURL *string `json:"logo_url,omitempty"`

	Font *BrandingFont `json:"font,omitempty"`
}

type BrandingColors struct {
	// Accent color
	Primary *string `json:"primary,omitempty"`

	// Page background color
	// Only one of PageBackground and PageBackgroundGradient should be set.
	// If both fields are set, PageBackground takes priority.
	PageBackground *string `json:"-"`

	// Page background gradient
	// Only one of PageBackground and PageBackgroundGradient should be set.
	// If both fields are set, PageBackground takes priority.
	PageBackgroundGradient *BrandingPageBackgroundGradient `json:"-"`
}

type BrandingPageBackgroundGradient struct {
	Type        *string `json:"type,omitempty"`
	Start       *string `json:"start,omitempty"`
	End         *string `json:"end,omitempty"`
	AngleDegree *int    `json:"angle_deg,omitempty"`
}

type jsonPageBackgroundSolid struct {
	PageBackground *string `json:"page_background,omitempty"`
}

type jsonPageBackgroundGradient struct {
	PageBackgroundGradient *BrandingPageBackgroundGradient `json:"page_background,omitempty"`
}

// MarshalJSON implements the json.Marshaler interface.
//
// It is required to handle the json field page_background, which can either
// be a hex color string, or an object describing a gradient.
func (bc *BrandingColors) MarshalJSON() ([]byte, error) {
	type brandingColors BrandingColors
	type brandingColorsWrapper struct {
		*brandingColors
		RawPageBackground interface{} `json:"page_background,omitempty"`
	}

	alias := &brandingColorsWrapper{(*brandingColors)(bc), nil}

	if bc.PageBackground != nil && bc.PageBackgroundGradient != nil {
		return nil, fmt.Errorf("only one of PageBackground and PageBackgroundGradient is allowed")
	} else if bc.PageBackground != nil {
		alias.RawPageBackground = bc.PageBackground
	} else if bc.PageBackgroundGradient != nil {
		alias.RawPageBackground = bc.PageBackgroundGradient
	}

	return json.Marshal(alias)
}

// UnmarshalJSON implements the json.Unmarshaler interface.
//
// It is required to handle the json field page_background, which can either
// be a hex color string, or an object describing a gradient.
func (bc *BrandingColors) UnmarshalJSON(data []byte) error {

	type brandingColors BrandingColors
	type brandingColorsWrapper struct {
		*brandingColors
		RawPageBackground json.RawMessage `json:"page_background,omitempty"`
	}

	alias := &brandingColorsWrapper{(*brandingColors)(bc), nil}

	err := json.Unmarshal(data, alias)
	if err != nil {
		return err
	}

	if alias.RawPageBackground != nil {

		var v interface{}
		err = json.Unmarshal(alias.RawPageBackground, &v)
		if err != nil {
			return err
		}

		switch rawPageBackground := v.(type) {
		case string:
			bc.PageBackground = &rawPageBackground

		case map[string]interface{}:
			var gradient BrandingPageBackgroundGradient
			err = json.Unmarshal(alias.RawPageBackground, &gradient)
			if err != nil {
				return err
			}
			bc.PageBackgroundGradient = &gradient

		default:
			return fmt.Errorf("unexpected type for field page_background")
		}
	}

	return nil
}

type BrandingFont struct {
	// URL for the custom font. Must use HTTPS.
	URL *string `json:"url,omitempty"`
}

type BrandingManager struct {
	*Management
}

func newBrandingManager(m *Management) *BrandingManager {
	return &BrandingManager{m}
}

// Retrieve various settings related to branding.
//
// See: https://auth0.com/docs/api/management/v2#!/Branding/get_branding
func (m *BrandingManager) Read() (*Branding, error) {
	branding := new(Branding)
	err := m.get(m.uri("branding"), branding)
	return branding, err
}

// Update various fields related to branding.
//
// See: https://auth0.com/docs/api/management/v2#!/Branding/patch_branding
func (m *BrandingManager) Update(t *Branding) (err error) {
	return m.patch(m.uri("branding"), t)
}
