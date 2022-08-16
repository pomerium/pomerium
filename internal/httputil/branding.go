package httputil

// The BrandingOptions customize the user info and error pages.
type BrandingOptions interface {
	GetPrimaryColor() string
	GetSecondaryColor() string
	GetDarkmodePrimaryColor() string
	GetDarkmodeSecondaryColor() string
	GetLogoUrl() string
	GetFaviconUrl() string
	GetErrorMessageFirstParagraph() string
}

// AddBrandingOptionsToMap adds the branding options to the map.
func AddBrandingOptionsToMap(dst map[string]any, brandingOptions BrandingOptions) {
	if brandingOptions == nil {
		return
	}

	if brandingOptions.GetPrimaryColor() != "" {
		dst["primaryColor"] = brandingOptions.GetPrimaryColor()
	}
	if brandingOptions.GetSecondaryColor() != "" {
		dst["secondaryColor"] = brandingOptions.GetSecondaryColor()
	}
	if brandingOptions.GetLogoUrl() != "" {
		dst["logoUrl"] = brandingOptions.GetLogoUrl()
	}
	if brandingOptions.GetFaviconUrl() != "" {
		dst["faviconUrl"] = brandingOptions.GetFaviconUrl()
	}
	if brandingOptions.GetErrorMessageFirstParagraph() != "" {
		dst["errorMessageFirstParagraph"] = brandingOptions.GetErrorMessageFirstParagraph()
	}
}
