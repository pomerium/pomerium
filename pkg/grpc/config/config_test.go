package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/proto"
)

func TestVersionedConfigIsApplicable(t *testing.T) {
	versions := map[string]string{
		"":    "v0.30.1-dev-12345+abcdef",
		"foo": "v0.1.0",
		"bar": "v0.2.0",
		"baz": "v0.3.0",
	}

	// no conditions
	assert.True(t, (&VersionedConfig{}).IsApplicable(versions))

	// overall version check
	assert.True(t, (&VersionedConfig{
		Conditions: []*VersionedConfig_Condition{{
			AtLeast: proto.String("v0.30.0"),
		}},
	}).IsApplicable(versions))
	assert.False(t, (&VersionedConfig{
		Conditions: []*VersionedConfig_Condition{{
			AtLeast: proto.String("v0.31.0"),
		}},
	}).IsApplicable(versions))
	assert.False(t, (&VersionedConfig{
		Conditions: []*VersionedConfig_Condition{{
			LessThan: proto.String("v0.30.0"),
		}},
	}).IsApplicable(versions))
	assert.True(t, (&VersionedConfig{
		Conditions: []*VersionedConfig_Condition{{
			LessThan: proto.String("v0.31.0"),
		}},
	}).IsApplicable(versions))

	// version ranges (both at_least and less_than together)
	assert.False(t, (&VersionedConfig{
		Conditions: []*VersionedConfig_Condition{{
			AtLeast:  proto.String("v0.29.0"),
			LessThan: proto.String("v0.30.0"),
		}},
	}).IsApplicable(versions))
	assert.True(t, (&VersionedConfig{
		Conditions: []*VersionedConfig_Condition{{
			AtLeast:  proto.String("v0.30.0"),
			LessThan: proto.String("v0.31.0"),
		}},
	}).IsApplicable(versions))
	assert.False(t, (&VersionedConfig{
		Conditions: []*VersionedConfig_Condition{{
			AtLeast:  proto.String("v0.31.0"),
			LessThan: proto.String("v0.32.0"),
		}},
	}).IsApplicable(versions))

	// feature component version checks
	assert.True(t, (&VersionedConfig{
		Conditions: []*VersionedConfig_Condition{{
			Feature: proto.String("foo"),
			AtLeast: proto.String("v0.1.0"),
		}},
	}).IsApplicable(versions))
	assert.False(t, (&VersionedConfig{
		Conditions: []*VersionedConfig_Condition{{
			Feature:  proto.String("bar"),
			LessThan: proto.String("v0.2.0"),
		}},
	}).IsApplicable(versions))

	// unknown feature
	assert.False(t, (&VersionedConfig{
		Conditions: []*VersionedConfig_Condition{{
			Feature: proto.String("unknown-feature"),
			AtLeast: proto.String("v0.0.0"),
		}},
	}).IsApplicable(versions))
	assert.True(t, (&VersionedConfig{
		Conditions: []*VersionedConfig_Condition{{
			Feature:  proto.String("unknown-feature"),
			LessThan: proto.String("v0.1.0"),
		}},
	}).IsApplicable(versions))
}
