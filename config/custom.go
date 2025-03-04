package config

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	goset "github.com/hashicorp/go-set/v3"
	"github.com/mitchellh/mapstructure"
	"github.com/volatiletech/null/v9"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v3"

	"github.com/pomerium/pomerium/internal/hashutil"
	"github.com/pomerium/pomerium/internal/httputil"
	"github.com/pomerium/pomerium/internal/urlutil"
	"github.com/pomerium/pomerium/pkg/policy/parser"
)

func decodeNullBoolHookFunc() mapstructure.DecodeHookFunc {
	return func(_, t reflect.Type, data any) (any, error) {
		if t != reflect.TypeOf(null.Bool{}) {
			return data, nil
		}

		bs, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		var value null.Bool
		err = json.Unmarshal(bs, &value)
		if err != nil {
			return nil, err
		}
		return value, nil
	}
}

// JWTClaimHeaders are headers to add to a request based on IDP claims.
type JWTClaimHeaders map[string]string

// NewJWTClaimHeaders creates a JWTClaimHeaders map from a slice of claims.
func NewJWTClaimHeaders(claims ...string) JWTClaimHeaders {
	hdrs := make(JWTClaimHeaders)
	for _, claim := range claims {
		k := httputil.PomeriumJWTHeaderName(claim)
		hdrs[k] = claim
	}
	return hdrs
}

// UnmarshalJSON unmarshals JSON data into the JWTClaimHeaders.
func (hdrs *JWTClaimHeaders) UnmarshalJSON(data []byte) error {
	var m map[string]any
	if json.Unmarshal(data, &m) == nil {
		*hdrs = make(map[string]string)
		for k, v := range m {
			str := fmt.Sprint(v)
			(*hdrs)[k] = str
		}
		return nil
	}

	var a []any
	if json.Unmarshal(data, &a) == nil {
		var vs []string
		for _, v := range a {
			vs = append(vs, fmt.Sprint(v))
		}
		*hdrs = NewJWTClaimHeaders(vs...)
		return nil
	}

	var s string
	if json.Unmarshal(data, &s) == nil {
		*hdrs = NewJWTClaimHeaders(strings.FieldsFunc(s, func(r rune) bool {
			return r == ',' || unicode.IsSpace(r)
		})...)
		return nil
	}

	return fmt.Errorf("JWTClaimHeaders must be an object or an array of values, got: %s", data)
}

// UnmarshalYAML uses UnmarshalJSON to unmarshal YAML data into the JWTClaimHeaders.
func (hdrs *JWTClaimHeaders) UnmarshalYAML(unmarshal func(any) error) error {
	var i any
	err := unmarshal(&i)
	if err != nil {
		return err
	}

	m, err := serializable(i)
	if err != nil {
		return err
	}

	bs, err := json.Marshal(m)
	if err != nil {
		return err
	}

	return hdrs.UnmarshalJSON(bs)
}

func decodeJWTClaimHeadersHookFunc() mapstructure.DecodeHookFunc {
	return func(_, t reflect.Type, data any) (any, error) {
		if t != reflect.TypeOf(JWTClaimHeaders{}) {
			return data, nil
		}

		bs, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		var hdrs JWTClaimHeaders
		err = json.Unmarshal(bs, &hdrs)
		if err != nil {
			return nil, err
		}
		return hdrs, nil
	}
}

// A StringSlice is a slice of strings.
type StringSlice []string

// NewStringSlice creates a new StringSlice.
func NewStringSlice(values ...string) StringSlice {
	return values
}

const (
	array = iota
	arrayValue
	object
	objectKey
	objectValue
)

// UnmarshalJSON unmarshals a JSON document into the string slice.
func (slc *StringSlice) UnmarshalJSON(data []byte) error {
	typeStack := []int{array}
	stateStack := []int{arrayValue}

	var vals []string
	dec := json.NewDecoder(bytes.NewReader(data))
	for {
		token, err := dec.Token()
		if err != nil {
			break
		}

		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '[':
				typeStack = append(typeStack, array)
				stateStack = append(stateStack, arrayValue)
			case '{':
				typeStack = append(typeStack, object)
				stateStack = append(stateStack, objectKey)
			case ']', '}':
				typeStack = typeStack[:len(typeStack)-1]
				stateStack = stateStack[:len(stateStack)-1]
			}
			continue
		}

		switch stateStack[len(stateStack)-1] {
		case objectKey:
			stateStack[len(stateStack)-1] = objectValue
		case objectValue:
			stateStack[len(stateStack)-1] = objectKey
			fallthrough
		default:
			switch t := token.(type) {
			case bool:
				vals = append(vals, fmt.Sprint(t))
			case float64:
				vals = append(vals, fmt.Sprint(t))
			case json.Number:
				vals = append(vals, fmt.Sprint(t))
			case string:
				vals = append(vals, t)
			default:
			}
		}
	}
	*slc = StringSlice(vals)
	return nil
}

// UnmarshalYAML unmarshals a YAML document into the string slice. UnmarshalJSON is
// reused as the actual implementation.
func (slc *StringSlice) UnmarshalYAML(unmarshal func(any) error) error {
	var i any
	err := unmarshal(&i)
	if err != nil {
		return err
	}
	bs, err := json.Marshal(i)
	if err != nil {
		return err
	}
	return slc.UnmarshalJSON(bs)
}

// WeightedURL is a way to specify an upstream with load balancing weight attached to it
type WeightedURL struct {
	URL url.URL
	// LbWeight is a relative load balancer weight for this upstream URL
	// zero means not assigned
	LbWeight uint32
}

// Validate validates that the WeightedURL is valid.
func (u *WeightedURL) Validate() error {
	if u.URL.Hostname() == "" {
		return errHostnameMustBeSpecified
	}
	if u.URL.Scheme == "" {
		return errSchemeMustBeSpecified
	}
	return nil
}

// ParseWeightedURL parses url that has an optional weight appended to it
func ParseWeightedURL(dst string) (*WeightedURL, error) {
	to, w, err := weightedString(dst)
	if err != nil {
		return nil, err
	}

	u, err := urlutil.ParseAndValidateURL(to)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", to, err)
	}

	if u.Hostname() == "" {
		return nil, errHostnameMustBeSpecified
	}

	return &WeightedURL{*u, w}, nil
}

// String returns the WeightedURL as a string.
func (u *WeightedURL) String() string {
	str := u.URL.String()
	if u.LbWeight == 0 {
		return str
	}
	return fmt.Sprintf("{url=%s, weight=%d}", str, u.LbWeight)
}

// WeightedURLs is a slice of WeightedURLs.
type WeightedURLs []WeightedURL

// ParseWeightedUrls parses
func ParseWeightedUrls(urls ...string) (WeightedURLs, error) {
	out := make([]WeightedURL, 0, len(urls))

	for _, dst := range urls {
		u, err := ParseWeightedURL(dst)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}

	if _, err := WeightedURLs(out).Validate(); err != nil {
		return nil, err
	}

	return out, nil
}

// HasWeight indicates if url group has weights assigned
type HasWeight bool

// Validate checks that URLs are valid, and either all or none have weights assigned
func (urls WeightedURLs) Validate() (HasWeight, error) {
	if len(urls) == 0 {
		return false, errEmptyUrls
	}

	noWeight := false
	hasWeight := false

	for i := range urls {
		if err := urls[i].Validate(); err != nil {
			return false, fmt.Errorf("%s: %w", urls[i].String(), err)
		}
		if urls[i].LbWeight == 0 {
			noWeight = true
		} else {
			hasWeight = true
		}
	}

	if noWeight == hasWeight {
		return false, errEndpointWeightsSpec
	}

	if noWeight {
		return false, nil
	}
	return true, nil
}

// Flatten converts weighted url array into indidual arrays of urls and weights
func (urls WeightedURLs) Flatten() ([]string, []uint32, error) {
	hasWeight, err := urls.Validate()
	if err != nil {
		return nil, nil, err
	}

	str := make([]string, 0, len(urls))
	wghts := make([]uint32, 0, len(urls))

	for i := range urls {
		str = append(str, urls[i].URL.String())
		wghts = append(wghts, urls[i].LbWeight)
	}

	if !hasWeight {
		return str, nil, nil
	}
	return str, wghts, nil
}

// PPLPolicy is a policy defined using PPL.
type PPLPolicy struct {
	*parser.Policy
}

// UnmarshalJSON parses JSON into a PPL policy.
func (ppl *PPLPolicy) UnmarshalJSON(data []byte) error {
	var err error
	ppl.Policy, err = parser.ParseJSON(bytes.NewReader(data))
	if err != nil {
		return err
	}
	return nil
}

// UnmarshalYAML parses YAML into a PPL policy.
func (ppl *PPLPolicy) UnmarshalYAML(unmarshal func(any) error) error {
	var i any
	err := unmarshal(&i)
	if err != nil {
		return err
	}
	bs, err := json.Marshal(i)
	if err != nil {
		return err
	}
	return ppl.UnmarshalJSON(bs)
}

func decodePPLPolicyHookFunc() mapstructure.DecodeHookFunc {
	return func(_, t reflect.Type, data any) (any, error) {
		if t != reflect.TypeOf(&PPLPolicy{}) {
			return data, nil
		}
		bs, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}
		var ppl PPLPolicy
		err = json.Unmarshal(bs, &ppl)
		if err != nil {
			return nil, err
		}
		return &ppl, nil
	}
}

// DecodePolicyBase64Hook returns a mapstructure decode hook for base64 data.
func DecodePolicyBase64Hook() mapstructure.DecodeHookFunc {
	return func(_, t reflect.Type, data any) (any, error) {
		if t != reflect.TypeOf([]Policy{}) {
			return data, nil
		}

		str, ok := data.([]string)
		if !ok {
			return data, nil
		}

		if len(str) != 1 {
			return nil, fmt.Errorf("base64 policy data: expecting 1, got %d", len(str))
		}

		bytes, err := base64.StdEncoding.DecodeString(str[0])
		if err != nil {
			return nil, fmt.Errorf("base64 decoding policy data: %w", err)
		}

		var out []map[any]any
		if err = yaml.Unmarshal(bytes, &out); err != nil {
			return nil, fmt.Errorf("parsing base64-encoded policy data as yaml: %w", err)
		}

		return out, nil
	}
}

// DecodePolicyHookFunc returns a Decode Hook for mapstructure.
func DecodePolicyHookFunc() mapstructure.DecodeHookFunc {
	return func(_, t reflect.Type, data any) (any, error) {
		if t != reflect.TypeOf(Policy{}) {
			return data, nil
		}

		// convert all keys to strings so that it can be serialized back to JSON
		// and read by jsonproto package into Envoy's cluster structure
		mp, err := serializable(data)
		if err != nil {
			return nil, err
		}
		ms, ok := mp.(map[string]any)
		if !ok {
			return nil, errKeysMustBeStrings
		}

		return parsePolicy(ms)
	}
}

func parsePolicy(src map[string]any) (out map[string]any, err error) {
	out = make(map[string]any, len(src))
	for k, v := range src {
		if k == toKey {
			if v, err = parseTo(v); err != nil {
				return nil, err
			}
		}
		out[k] = v
	}

	// also, interpret the entire policy as Envoy's Cluster document to derive its options
	out[envoyOptsKey], err = parseEnvoyClusterOpts(src)
	if err != nil {
		return nil, err
	}

	return out, nil
}

func parseTo(raw any) ([]WeightedURL, error) {
	rawBS, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var slc StringSlice
	err = json.Unmarshal(rawBS, &slc)
	if err != nil {
		return nil, err
	}

	return ParseWeightedUrls(slc...)
}

// parses URL followed by weighted
func weightedString(str string) (string, uint32, error) {
	i := strings.IndexRune(str, ',')
	if i < 0 {
		return str, 0, nil
	}

	w, err := strconv.ParseUint(str[i+1:], 10, 32)
	if err != nil {
		return "", 0, err
	}

	if w == 0 {
		return "", 0, errZeroWeight
	}

	return str[:i], uint32(w), nil
}

// parseEnvoyClusterOpts parses src as envoy cluster spec https://www.envoyproxy.io/docs/envoy/latest/api-v3/config/cluster/v3/cluster.proto
// on top of some pre-filled default values
func parseEnvoyClusterOpts(src map[string]any) (*envoy_config_cluster_v3.Cluster, error) {
	c := new(envoy_config_cluster_v3.Cluster)
	if err := parseJSONPB(src, c, protoPartial); err != nil {
		return nil, err
	}

	return c, nil
}

// parseJSONPB takes an intermediate representation and parses it using protobuf parser
// that correctly handles oneof and other data types
func parseJSONPB(src map[string]any, dst proto.Message, opts protojson.UnmarshalOptions) error {
	data, err := json.Marshal(src)
	if err != nil {
		return err
	}

	return opts.Unmarshal(data, dst)
}

// decodeSANMatcherHookFunc returns a decode hook for the SANMatcher type.
func decodeSANMatcherHookFunc() mapstructure.DecodeHookFunc {
	return func(_, t reflect.Type, data any) (any, error) {
		if t != reflect.TypeOf(SANMatcher{}) {
			return data, nil
		}

		b, err := json.Marshal(data)
		if err != nil {
			return nil, err
		}

		var m SANMatcher
		if err := json.Unmarshal(b, &m); err != nil {
			return nil, err
		}
		return m, nil
	}
}

func decodeStringToMapHookFunc() mapstructure.DecodeHookFunc {
	return mapstructure.DecodeHookFuncValue(func(f, t reflect.Value) (any, error) {
		if f.Kind() != reflect.String || t.Kind() != reflect.Map {
			return f.Interface(), nil
		}

		err := json.Unmarshal([]byte(f.Interface().(string)), t.Addr().Interface())
		if err != nil {
			return nil, err
		}

		return t.Interface(), nil
	})
}

// serializable converts mapstructure nested map into map[string]any that is serializable to JSON
func serializable(in any) (any, error) {
	switch typed := in.(type) {
	case map[any]any:
		m := make(map[string]any)
		for k, v := range typed {
			kstr, ok := k.(string)
			if !ok {
				return nil, errKeysMustBeStrings
			}
			val, err := serializable(v)
			if err != nil {
				return nil, err
			}
			m[kstr] = val
		}
		return m, nil
	case []any:
		out := make([]any, 0, len(typed))
		for _, elem := range typed {
			val, err := serializable(elem)
			if err != nil {
				return nil, err
			}
			out = append(out, val)
		}
		return out, nil
	default:
		return in, nil
	}
}

type JWTGroupsFilter struct {
	set *goset.Set[string]
}

func NewJWTGroupsFilter(groups []string) JWTGroupsFilter {
	var s *goset.Set[string]
	if len(groups) > 0 {
		s = goset.From(groups)
	}
	return JWTGroupsFilter{s}
}

func (f JWTGroupsFilter) Enabled() bool {
	return f.set != nil
}

func (f JWTGroupsFilter) IsAllowed(group string) bool {
	return f.set == nil || f.set.Contains(group)
}

func (f JWTGroupsFilter) ToSlice() []string {
	if f.set == nil {
		return nil
	}
	return slices.Sorted(f.set.Items())
}

func (f JWTGroupsFilter) Hash() (uint64, error) {
	return hashutil.Hash(f.ToSlice())
}

func (f JWTGroupsFilter) Equal(other JWTGroupsFilter) bool {
	if f.set == nil && other.set == nil {
		return true
	} else if f.set == nil || other.set == nil {
		return false
	}
	return f.set.Equal(other.set)
}

type JWTIssuerFormat string

const (
	JWTIssuerFormatHostOnly JWTIssuerFormat = "hostOnly"
	JWTIssuerFormatURI      JWTIssuerFormat = "uri"
)
