// Package config contains protobuf definitions for config.
package config

import (
	_ "embed"

	gendoc "github.com/pseudomuto/protoc-gen-doc"

	"github.com/pomerium/pomerium/internal/jsonutil"
)

//go:embed config.pb.json
var RawDocs []byte

var Docs = jsonutil.MustParse[gendoc.Template](RawDocs)

// IsSet returns true if one of the route redirect options has been chosen.
func (rr *RouteRedirect) IsSet() bool {
	if rr == nil {
		return false
	}

	return rr.StripQuery != nil ||
		rr.ResponseCode != nil ||
		rr.PrefixRewrite != nil ||
		rr.PathRedirect != nil ||
		rr.PortRedirect != nil ||
		rr.HostRedirect != nil ||
		rr.SchemeRedirect != nil ||
		rr.HttpsRedirect != nil
}

func (x *Config) GetId() string { //nolint
	return x.Name
}

func (x *Settings) HasBrandingOptions() bool {
	return x.GetPrimaryColor() != "" ||
		x.GetSecondaryColor() != "" ||
		x.GetDarkmodePrimaryColor() != "" ||
		x.GetDarkmodeSecondaryColor() != "" ||
		x.GetLogoUrl() != "" ||
		x.GetFaviconUrl() != "" ||
		x.GetErrorMessageFirstParagraph() != ""
}
