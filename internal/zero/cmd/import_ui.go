package cmd

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/charmbracelet/lipgloss"
	http_connection_managerv3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	"github.com/muesli/termenv"
	"github.com/pomerium/pomerium/config"
	"github.com/pomerium/pomerium/internal/log"
	configpb "github.com/pomerium/pomerium/pkg/grpc/config"
	cluster_api "github.com/pomerium/pomerium/pkg/zero/cluster"
	"github.com/pomerium/pomerium/pkg/zero/importutil"
	"github.com/pomerium/protoutil/fieldmasks"
	"github.com/pomerium/protoutil/paths"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/reflect/protopath"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

type onCursorUpdate struct {
	Field interface{ Cursor() int }
}

func (u onCursorUpdate) Hash() (uint64, error) {
	return uint64(u.Field.Cursor()), nil
}

var (
	yellowText = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(3))
	faintText  = lipgloss.NewStyle().Faint(true).UnsetForeground()
	redText    = lipgloss.NewStyle().Foreground(lipgloss.ANSIColor(1))
)

func errText(err error) string {
	return redText.Render(fmt.Sprintf("(error: %v)", err))
}

func certInfoFromSettingsCertificate(v protoreflect.Value) string {
	switch v := v.Interface().(type) {
	case protoreflect.List:
		buf := bytes.Buffer{}
		for i, l := 0, v.Len(); i < l; i++ {
			crtBytes := string(v.Get(i).Message().Interface().(*configpb.Settings_Certificate).GetCertBytes())
			buf.WriteString(crtBytes)
			if i < l-1 {
				buf.WriteRune('\n')
			}
		}
		return certInfoFromBytes(buf.Bytes())
	case protoreflect.Message:
		crtBytes := string(v.Interface().(*configpb.Settings_Certificate).GetCertBytes())
		return certInfoFromBytes([]byte(crtBytes))
	default:
		panic(fmt.Sprintf("bug: unexpected value type %T", v))
	}
}

func certInfoFromBase64(v protoreflect.Value) string {
	crtBytes, err := base64.StdEncoding.DecodeString(v.String())
	if err != nil {
		return errText(err)
	}
	return certInfoFromBytes(crtBytes)
}

func certInfoFromBytes(b []byte) string {
	if len(b) == 0 {
		return faintText.Render("(empty)")
	}
	block, rest := pem.Decode(b)
	if block == nil {
		return errText(errors.New("no PEM data found"))
	}
	extraBlocks := []*pem.Block{}
	for len(rest) > 0 {
		block, rest = pem.Decode(rest)
		if block != nil {
			extraBlocks = append(extraBlocks, block)
		}
	}
	blockType := block.Type
	var info string
	switch block.Type {
	case "X509 CRL":
		crl, err := x509.ParseRevocationList(block.Bytes)
		if err != nil {
			return errText(err)
		}
		info = fmt.Sprintf("%d entries", len(crl.RevokedCertificateEntries))
	default:
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return errText(err)
		}
		info = *importutil.GenerateCertName(cert)
	}
	out := yellowText.Render(fmt.Sprintf("(%s: %s)", blockType, info))
	if len(extraBlocks) > 0 {
		s := ""
		if len(extraBlocks) != 1 {
			s = "s"
		}
		out += faintText.Render(fmt.Sprintf(" ...+%d block%s", len(extraBlocks), s))
	}
	return out
}

func secret(s protoreflect.Value) string {
	length := len(s.String())
	return yellowText.Render(fmt.Sprintf("(secret: %d bytes)", length))
}

var customSettingsInfoByPath = map[string]func(v protoreflect.Value) string{
	"(pomerium.config.Settings).metrics_certificate":                                    certInfoFromSettingsCertificate,
	"(pomerium.config.Settings).metrics_client_ca":                                      certInfoFromBase64,
	"(pomerium.config.Settings).certificates":                                           certInfoFromSettingsCertificate,
	"(pomerium.config.Settings).certificate_authority":                                  certInfoFromBase64,
	"(pomerium.config.Settings).downstream_mtls.ca":                                     certInfoFromBase64,
	"(pomerium.config.Settings).downstream_mtls.crl":                                    certInfoFromBase64,
	"(pomerium.config.Settings).shared_secret":                                          secret,
	"(pomerium.config.Settings).cookie_secret":                                          secret,
	"(pomerium.config.Settings).google_cloud_serverless_authentication_service_account": secret,
	"(pomerium.config.Settings).idp_client_secret":                                      secret,
	"(pomerium.config.Settings).databroker_storage_connection_string":                   secret,
}

type ImportHints struct {
	// Indicates that the field is ignored during Zero import
	Ignored bool
	// Indicates that the field is entirely unsupported by Zero, and will likely
	// break an existing configuration if imported. If any of these fields are
	// selected, an error will be displayed.
	Unsupported bool
	// An optional note explaining why a field is ignored or unsupported, if
	// additional context would be helpful. This message will be user facing.
	Note string
	// Indicates that the field is treated as a secret, and will be encrypted.
	Secret bool
}

const (
	noteSplitService           = "split-service mode"
	noteEnterpriseOnly         = "enterprise only"
	noteFeatureNotYetAvailable = "feature not yet available"
)

func noteCertificate(n int) string {
	suffix := ""
	if n != 1 {
		suffix = "s"
	}
	return fmt.Sprintf("+%d certificate%s", n, suffix)
}

func notePolicy(n int) string {
	suffix := "y"
	if n != 1 {
		suffix = "ies"
	}
	return fmt.Sprintf("+%d polic%s", n, suffix)
}

func computeSettingsImportHints(cfg *configpb.Config) map[string]ImportHints {
	m := map[string]ImportHints{
		"authenticate_callback_path":             {Ignored: true},
		"shared_secret":                          {Ignored: true},
		"cookie_secret":                          {Ignored: true},
		"signing_key":                            {Ignored: true},
		"authenticate_internal_service_url":      {Unsupported: true, Note: noteSplitService},
		"authorize_internal_service_url":         {Unsupported: true, Note: noteSplitService},
		"databroker_internal_service_url":        {Unsupported: true, Note: noteSplitService},
		"derive_tls":                             {Unsupported: true, Note: noteSplitService},
		"audit_key":                              {Unsupported: true, Note: noteEnterpriseOnly},
		"primary_color":                          {Unsupported: true, Note: noteEnterpriseOnly},
		"secondary_color":                        {Unsupported: true, Note: noteEnterpriseOnly},
		"darkmode_primary_color":                 {Unsupported: true, Note: noteEnterpriseOnly},
		"darkmode_secondary_color":               {Unsupported: true, Note: noteEnterpriseOnly},
		"logo_url":                               {Unsupported: true, Note: noteEnterpriseOnly},
		"favicon_url":                            {Unsupported: true, Note: noteEnterpriseOnly},
		"error_message_first_paragraph":          {Unsupported: true, Note: noteEnterpriseOnly},
		"use_proxy_protocol":                     {Unsupported: true, Note: noteFeatureNotYetAvailable},
		"programmatic_redirect_domain_whitelist": {Unsupported: true, Note: noteFeatureNotYetAvailable},
		"grpc_client_timeout":                    {Unsupported: true, Note: noteFeatureNotYetAvailable},
		"grpc_client_dns_roundrobin":             {Unsupported: true, Note: noteFeatureNotYetAvailable},
		"envoy_bind_config_freebind":             {Unsupported: true, Note: noteFeatureNotYetAvailable},
		"envoy_bind_config_source_address":       {Unsupported: true, Note: noteFeatureNotYetAvailable},
		"google_cloud_serverless_authentication_service_account": {Secret: true},
		"idp_client_secret":                    {Secret: true},
		"databroker_storage_connection_string": {Secret: true},
		"metrics_certificate":                  {Unsupported: true, Note: noteFeatureNotYetAvailable},
		"metrics_client_ca":                    {Unsupported: true, Note: noteFeatureNotYetAvailable},
		// "metrics_certificate":                  {Note: noteCertificate(1)},
		// "metrics_client_ca":                    {Note: noteCertificate(1)},
		"certificate_authority": {Note: noteCertificate(1)},
		"certificates":          {Note: noteCertificate(len(cfg.GetSettings().GetCertificates()))},
		"downstream_mtls.crl":   {Unsupported: true, Note: noteFeatureNotYetAvailable},
		"downstream_mtls.ca":    {Note: noteCertificate(1)},
	}
	if dm := cfg.GetSettings().GetDownstreamMtls(); dm != nil {
		if dm.Enforcement != nil {
			switch *dm.Enforcement {
			case configpb.MtlsEnforcementMode_POLICY:
			case configpb.MtlsEnforcementMode_POLICY_WITH_DEFAULT_DENY:
			case configpb.MtlsEnforcementMode_REJECT_CONNECTION:
				// this is a special case - zero does not support this mode, but we cannot continue
				// with a partial import because it fundamentally changes the behavior of all routes
				// and policies in the system
				log.Fatal().Msg("downstream mtls enforcement mode 'reject_connection' is not supported")
			}
		}
	}
	if cfg.GetSettings().GetServices() != "all" {
		m["services"] = ImportHints{Ignored: true, Note: `only "all" is supported`}
	}
	if cfg.GetSettings().GetCodecType() != http_connection_managerv3.HttpConnectionManager_AUTO {
		m["codec_type"] = ImportHints{Ignored: true, Note: `only "auto" is supported`}
	}
	return m
}

type ImportUI struct {
	form             *huh.Form
	selectedSettings []string
	selectedRoutes   []string
}

func NewImportUI(cfg *configpb.Config, quotas *cluster_api.ConfigQuotas) *ImportUI {
	settingsImportHints := computeSettingsImportHints(cfg)

	presentSettings := fieldmasks.Leaves(
		fieldmasks.Diff(
			config.NewDefaultOptions().ToProto().GetSettings().ProtoReflect(),
			cfg.GetSettings().ProtoReflect(),
		),
		cfg.Settings.ProtoReflect().Descriptor(),
	)
	slices.Sort(presentSettings.Paths)
	settingsOptions := huh.NewOptions(presentSettings.Paths...)

	ui := &ImportUI{
		selectedSettings: slices.Clone(presentSettings.Paths),
	}

	for i, value := range presentSettings.Paths {
		if hints, ok := settingsImportHints[value]; ok {
			switch {
			case hints.Ignored:
				note := ""
				if hints.Note != "" {
					note = fmt.Sprintf(": %s", hints.Note)
				}
				settingsOptions[i].Key = fmt.Sprintf("\x1b[9m%s\x1b[29m \x1b[2m(ignored%s)\x1b[22m", settingsOptions[i].Key, note)
				ui.selectedSettings[i] = ""
			case hints.Unsupported:
				note := ""
				if hints.Note != "" {
					note = fmt.Sprintf(": %s", hints.Note)
				}
				settingsOptions[i].Key = fmt.Sprintf("\x1b[9m%s\x1b[29m \x1b[2m(unsupported%s)\x1b[22m", settingsOptions[i].Key, note)
				ui.selectedSettings[i] = ""
			case hints.Secret:
				settingsOptions[i].Key += " \x1b[2m(secret)\x1b[22m"
			default:
				if hints.Note != "" {
					settingsOptions[i].Key += fmt.Sprintf(" \x1b[2m(%s)\x1b[22m", hints.Note)
				}
			}
		}
	}
	ui.selectedSettings = slices.DeleteFunc(ui.selectedSettings, func(s string) bool {
		return s == ""
	})
	settingsSelect := huh.NewMultiSelect[string]().
		Filterable(false).
		Title("Import Settings").
		Description("Choose settings to import from your existing configuration").
		Options(settingsOptions...).
		Validate(func(selected []string) error {
			var unsupportedCount int
			for _, s := range selected {
				if hints, ok := settingsImportHints[s]; ok && hints.Unsupported {
					unsupportedCount++
				}
			}
			if unsupportedCount == 1 {
				return fmt.Errorf("1 selected setting is unsupported")
			} else if unsupportedCount > 1 {
				return fmt.Errorf("%d selected settings are unsupported", unsupportedCount)
			}
			return nil
		}).
		Value(&ui.selectedSettings)
	settingsSelect.Focus()

	escapeNoteText := strings.NewReplacer(
		"*", "\\*",
		"_", "\\_",
		"`", "\\`",
	)
	settingsNoteDescription := func(idx int) string {
		if idx < 0 || idx > len(presentSettings.Paths) {
			return ""
		}
		path, err := paths.ParseFrom(cfg.Settings.ProtoReflect().Descriptor(), "."+presentSettings.Paths[idx])
		if err != nil {
			return errText(err)
		}
		val, err := paths.Evaluate(cfg.Settings, path)
		if err != nil {
			return errText(err)
		}
		if infoFunc, ok := customSettingsInfoByPath[path.String()]; ok {
			return escapeNoteText.Replace(infoFunc(val))
		}
		return escapeNoteText.Replace(formatValue(path, val))
	}
	settingsNote := huh.NewNote().
		Title(fmt.Sprintf("Value: %s", presentSettings.Paths[0])).
		TitleFunc(func() string {
			return fmt.Sprintf("Value: %s", presentSettings.Paths[settingsSelect.Cursor()])
		}, onCursorUpdate{settingsSelect}).
		Description(settingsNoteDescription(0)).
		DescriptionFunc(func() string {
			return settingsNoteDescription(settingsSelect.Cursor())
		}, onCursorUpdate{settingsSelect}).
		Height(3)
	settingsNote.Focus()

	routeNames := make([]string, len(cfg.Routes))
	for i, name := range importutil.GenerateRouteNames(cfg.Routes) {
		routeNames[i] = name
		cfg.Routes[i].Name = name
	}
	routeOptions := huh.NewOptions(routeNames...)
	for i, name := range routeNames {
		if i < quotas.Routes {
			ui.selectedRoutes = append(ui.selectedRoutes, name)
		}
		if n := includedCertificatesInRoute(cfg.Routes[i]); n > 0 {
			routeOptions[i].Key += fmt.Sprintf(" \x1b[2m(%s)\x1b[22m", noteCertificate(n))
		}
		if n := includedPoliciesInRoute(cfg.Routes[i]); n > 0 {
			routeOptions[i].Key += fmt.Sprintf(" \x1b[2m(%s)\x1b[22m", notePolicy(n))
		}
	}

	routesSelectDescription := func() string {
		return fmt.Sprintf(`
Choose routes to import from your existing configuration. Policies and
certificates associated with selected routes will also be imported.

Pomerium Zero routes require unique names. We've generated default names
from the contents of each route, but these can always be changed later on.

Selected: %d/%d`[1:], len(ui.selectedRoutes), quotas.Routes)
	}
	topMarginLines := 1 + len(strings.Split(routesSelectDescription(), "\n"))
	routesSelect := huh.NewMultiSelect[string]().
		Filterable(true).
		Title("Import Routes").
		Description(routesSelectDescription()).
		DescriptionFunc(routesSelectDescription, &ui.selectedRoutes).
		Height(min(30, len(cfg.Routes)) + topMarginLines).
		Options(routeOptions...).
		Validate(func(_ []string) error {
			if len(ui.selectedRoutes) > quotas.Routes {
				return fmt.Errorf("A maximum of %d routes can be imported", quotas.Routes) //nolint:stylecheck
			}
			return nil
		}).
		Value(&ui.selectedRoutes)

	var (
		labelFrom     = yellowText.Render("    from: ")
		labelPath     = yellowText.Render("    path: ")
		labelPrefix   = yellowText.Render("  prefix: ")
		labelRegex    = yellowText.Render("   regex: ")
		labelTo       = yellowText.Render("      to: ")
		labelRedirect = yellowText.Render("redirect: ")
		labelResponse = yellowText.Render("response: ")
	)
	routesNoteDescription := func(idx int) string {
		selected := cfg.Routes[idx]
		var b strings.Builder
		b.WriteString(labelFrom)
		b.WriteString(selected.From)
		switch {
		case selected.Path != "":
			b.WriteRune('\n')
			b.WriteString(labelPath)
			b.WriteString(selected.Path)
		case selected.Prefix != "":
			b.WriteRune('\n')
			b.WriteString(labelPrefix)
			b.WriteString(selected.Prefix)
		case selected.Regex != "":
			b.WriteRune('\n')
			b.WriteString(labelRegex)
			b.WriteString(selected.Regex)
		}
		switch {
		case len(selected.To) > 0:
			b.WriteRune('\n')
			b.WriteString(labelTo)
			b.WriteString(selected.To[0])
			for _, t := range selected.To[1:] {
				b.WriteString(", ")
				b.WriteString(t)
			}
		case selected.Redirect != nil:
			b.WriteRune('\n')
			b.WriteString(labelRedirect)
			b.WriteString(selected.Redirect.String())
		case selected.Response != nil:
			b.WriteRune('\n')
			b.WriteString(labelResponse)
			b.WriteString(fmt.Sprint(selected.Response.Status))
			b.WriteRune(' ')
			b.WriteString(strconv.Quote(selected.Response.Body))
		}
		return b.String()
	}
	routesNote := huh.NewNote().
		Title("Route Info").
		Description(routesNoteDescription(0)).
		DescriptionFunc(func() string {
			return routesNoteDescription(routesSelect.Cursor())
		}, onCursorUpdate{routesSelect}).Height(3)
	routesNote.Focus()

	ui.form = huh.NewForm(
		huh.NewGroup(settingsSelect, settingsNote),
		huh.NewGroup(routesSelect, routesNote),
	).WithTheme(huh.ThemeBase16())
	return ui
}

func (ui *ImportUI) Run(ctx context.Context) error {
	if lipgloss.ColorProfile() == termenv.Ascii &&
		!termenv.EnvNoColor() && os.Getenv("TERM") != "dumb" {
		lipgloss.SetColorProfile(termenv.ANSI)
	}
	return ui.form.RunWithContext(ctx)
}

func (ui *ImportUI) ApplySelections(cfg *configpb.Config) {
	fieldmasks.ExclusiveKeep(cfg.Settings, &fieldmaskpb.FieldMask{
		Paths: ui.selectedSettings,
	})
	cfg.Routes = slices.DeleteFunc(cfg.Routes, func(route *configpb.Route) bool {
		return !slices.Contains(ui.selectedRoutes, route.Name)
	})
}

func includedCertificatesInRoute(route *configpb.Route) int {
	n := 0
	if route.TlsClientCert != "" && route.TlsClientKey != "" {
		n++
	}
	if route.TlsCustomCa != "" {
		n++
	}
	if route.TlsDownstreamClientCa != "" {
		n++
	}
	return n
}

func includedPoliciesInRoute(route *configpb.Route) int {
	n := 0
	for _, policy := range route.PplPolicies {
		// skip over common generated policies
		switch string(policy.Raw) {
		case `[{"allow":{"or":[{"accept":true}]}}]`:
		case `[{"allow":{"or":[{"authenticated_user":true}]}}]`:
		case `[{"allow":{"or":[{"cors_preflight":true}]}}]`:
		default:
			n++
		}
	}
	return n
}

func formatValue(path protopath.Path, val protoreflect.Value) string {
	switch vi := val.Interface().(type) {
	case protoreflect.Message:
		jsonData, err := protojson.Marshal(vi.Interface())
		if err != nil {
			return err.Error()
		}
		return string(jsonData)
	case protoreflect.List:
		values := []string{}
		for i := 0; i < vi.Len(); i++ {
			values = append(values, formatValue(path, vi.Get(i)))
		}
		return renderStringSlice(values)
	case protoreflect.Map:
		values := []string{}
		vi.Range(func(mk protoreflect.MapKey, v protoreflect.Value) bool {
			values = append(values, mk.String()+yellowText.Render("=")+formatValue(path, v))
			return true
		})
		slices.Sort(values)
		return renderStringSlice(values)
	case protoreflect.EnumNumber:
		var field protoreflect.FieldDescriptor
		switch step := path.Index(-1); step.Kind() {
		case protopath.FieldAccessStep:
			field = step.FieldDescriptor()
		case protopath.ListIndexStep, protopath.MapIndexStep:
			field = path.Index(-2).FieldDescriptor()
		}
		if field != nil {
			return strings.ToLower(string(field.Enum().Values().ByNumber(vi).Name()))
		}
		return fmt.Sprint(vi)
	default:
		return val.String()
	}
}

func renderStringSlice(values []string) string {
	return yellowText.Render("[") + strings.Join(values, yellowText.Render(", ")) + yellowText.Render("]")
}
