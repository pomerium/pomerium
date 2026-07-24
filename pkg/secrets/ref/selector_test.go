package ref

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestApplySelector(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		payload   string
		selector  string
		want      string
		wantErr   bool
		wantErrIs error
	}{
		{name: "empty selector returns raw", payload: "s3cr3t\x00\xff", selector: "", want: "s3cr3t\x00\xff"},
		{name: "nested string", payload: `{"data":{"token":"s3cr3t"}}`, selector: "data.token", want: "s3cr3t"},
		{name: "top-level string", payload: `{"token":"s3cr3t"}`, selector: "token", want: "s3cr3t"},
		{name: "number canonical", payload: `{"n":42}`, selector: "n", want: "42"},
		{name: "float canonical", payload: `{"n":42.5}`, selector: "n", want: "42.5"},
		{name: "bool true", payload: `{"b":true}`, selector: "b", want: "true"},
		{name: "bool false", payload: `{"b":false}`, selector: "b", want: "false"},
		{name: "non-json payload", payload: "not json", selector: "data", wantErr: true},
		{name: "missing key", payload: `{"data":{}}`, selector: "data.token", wantErr: true, wantErrIs: ErrSelectorNotFound},
		{name: "missing top key", payload: `{"other":1}`, selector: "token", wantErr: true, wantErrIs: ErrSelectorNotFound},
		{name: "descend into scalar", payload: `{"data":"x"}`, selector: "data.token", wantErr: true, wantErrIs: ErrSelectorNotFound},
		{name: "object value", payload: `{"data":{"token":"x"}}`, selector: "data", wantErr: true},
		{name: "array value", payload: `{"data":[1,2]}`, selector: "data", wantErr: true},
		{name: "null value", payload: `{"data":null}`, selector: "data", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := ApplySelector([]byte(tt.payload), tt.selector)
			if tt.wantErr {
				require.Error(t, err)
				if tt.wantErrIs != nil {
					assert.True(t, errors.Is(err, tt.wantErrIs), "want errors.Is(%v, %v)", err, tt.wantErrIs)
				}
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, string(got))
		})
	}
}

func TestApplySelectorNoValueInError(t *testing.T) {
	t.Parallel()

	const sentinel = "s3cr3t"

	// Missing-key error over a payload that contains the sentinel value.
	_, err := ApplySelector([]byte(`{"data":{"other":"`+sentinel+`"}}`), "data.token")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), sentinel)

	// Non-scalar (object) error over a payload containing the sentinel.
	_, err = ApplySelector([]byte(`{"data":{"token":"`+sentinel+`"}}`), "data")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), sentinel)

	// Non-JSON payload that is itself the sentinel.
	_, err = ApplySelector([]byte(sentinel), "data")
	require.Error(t, err)
	assert.NotContains(t, err.Error(), sentinel)
}
