// Package config contains protobuf definitions for config.
package config

import (
	"github.com/Masterminds/semver/v3"
)

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

func (x *VersionedConfig) IsApplicable(versions map[string]string) bool {
	for _, c := range x.GetConditions() {
		if !c.IsApplicable(versions) {
			return false
		}
	}
	return true
}

func (c *VersionedConfig_Condition) IsApplicable(versions map[string]string) bool {
	v, exists := versions[c.GetFeature()]
	version := parseSemVer(v)
	if c.AtLeast != nil {
		if !exists {
			return false
		}
		required, _ := semver.NewVersion(*c.AtLeast)
		if !version.GreaterThanEqual(required) {
			return false
		}
	}
	if c.LessThan != nil && exists {
		required, _ := semver.NewVersion(*c.LessThan)
		if !version.LessThan(required) {
			return false
		}
	}
	return true
}

func parseSemVer(version string) *semver.Version {
	v, _ := semver.NewVersion(version)
	if v == nil {
		return nil
	}
	v2, _ := v.SetPrerelease("")
	return &v2
}
