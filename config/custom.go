package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"

	envoy_config_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	"github.com/mitchellh/mapstructure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// A StringSlice is a slice of strings.
type StringSlice []string

// NewStringSlice creatse a new StringSlice.
func NewStringSlice(values ...string) StringSlice {
	return StringSlice(values)
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
func (slc *StringSlice) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var i interface{}
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

// ParseWeightedURL parses url that has an optional weight appended to it
func ParseWeightedURL(dst string) (*WeightedURL, error) {
	to, w, err := weightedString(dst)
	if err != nil {
		return nil, err
	}

	u, err := url.Parse(to)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", to, err)
	}

	return &WeightedURL{*u, w}, nil
}

// ParseWeightedUrls parses
func ParseWeightedUrls(urls []string) ([]WeightedURL, error) {
	out := make([]WeightedURL, 0, len(urls))

	for _, dst := range urls {
		u, err := ParseWeightedURL(dst)
		if err != nil {
			return nil, err
		}
		out = append(out, *u)
	}

	if _, _, err := FlattenURLs(out); err != nil {
		return nil, err
	}

	return out, nil
}

// FlattenURLs converts weighted url array into indidual arrays of urls and weights
func FlattenURLs(urls []WeightedURL) ([]string, []uint32, error) {
	noWeight := false
	hasWeight := false

	str := make([]string, 0, len(urls))
	wghts := make([]uint32, 0, len(urls))

	for i := range urls {
		str = append(str, urls[i].URL.String())
		wghts = append(wghts, urls[i].LbWeight)

		if wghts[i] == 0 {
			noWeight = true
		} else {
			hasWeight = true
		}
	}

	if noWeight == hasWeight {
		return nil, nil, errEndpointWeightsSpec
	}

	if noWeight {
		return str, nil, nil
	}
	return str, wghts, nil
}

// DecodeOptionsHookFunc returns a decode hook that will attempt to convert any type to a StringSlice.
func DecodeOptionsHookFunc() mapstructure.DecodeHookFunc {
	return func(f, t reflect.Type, data interface{}) (interface{}, error) {
		if t != reflect.TypeOf(Options{}) {
			return data, nil
		}

		m, ok := data.(map[string]interface{})
		if !ok {
			return data, nil
		}

		ps, ok := m[policyKey].([]interface{})
		if !ok {
			return data, nil
		}

		for _, p := range ps {
			pm, ok := p.(map[interface{}]interface{})
			if !ok {
				continue
			}

			envoyOpts, err := parseEnvoyClusterOpts(pm)
			if err != nil {
				return nil, err
			}
			pm[envoyOptsKey] = envoyOpts

			rawTo, ok := pm[toKey]
			if !ok {
				continue
			}
			to, err := parseTo(rawTo)
			if err != nil {
				return nil, err
			}
			pm[toKey] = to
		}

		return data, nil
	}
}

func parseTo(raw interface{}) ([]WeightedURL, error) {
	rawBS, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var slc StringSlice
	err = json.Unmarshal(rawBS, &slc)
	if err != nil {
		return nil, err
	}

	return ParseWeightedUrls(slc)
}

func weightedStrings(src StringSlice) (endpoints StringSlice, weights []uint32, err error) {
	weights = make([]uint32, len(src))
	endpoints = make([]string, len(src))

	noWeight := false
	hasWeight := false
	for i, str := range src {
		endpoints[i], weights[i], err = weightedString(str)
		if err != nil {
			return nil, nil, err
		}
		if weights[i] == 0 {
			noWeight = true
		} else {
			hasWeight = true
		}
	}

	if noWeight == hasWeight {
		return nil, nil, errEndpointWeightsSpec
	}

	if noWeight {
		return endpoints, nil, nil
	}
	return endpoints, weights, nil
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
func parseEnvoyClusterOpts(src interface{}) (*envoy_config_cluster_v3.Cluster, error) {
	c := new(envoy_config_cluster_v3.Cluster)
	if err := parseJSONPB(src, c, protoPartial); err != nil {
		return nil, err
	}

	return c, nil
}

// parseJSONPB takes an intermediate representation and parses it using protobuf parser
// that correctly handles oneof and other data types
func parseJSONPB(raw interface{}, dst proto.Message, opts protojson.UnmarshalOptions) error {
	ms, err := serializable(raw)
	if err != nil {
		return err
	}

	data, err := json.Marshal(ms)
	if err != nil {
		return err
	}

	return opts.Unmarshal(data, dst)
}

// serializable converts mapstructure nested map into map[string]interface{} that is serializable to JSON
func serializable(in interface{}) (interface{}, error) {
	switch typed := in.(type) {
	case map[interface{}]interface{}:
		m := make(map[string]interface{})
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
	case []interface{}:
		out := make([]interface{}, 0, len(typed))
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
