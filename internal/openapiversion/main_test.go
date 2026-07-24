package main

import "testing"

func TestSetInfoVersion(t *testing.T) {
	t.Parallel()

	const version = "v1.2.3"

	cases := []struct {
		name string
		in   string
		want string
	}{
		{
			name: "inserts when absent",
			in:   "openapi: 3.1.0\ninfo:\n  title: API\npaths: {}\n",
			want: "openapi: 3.1.0\ninfo:\n  version: v1.2.3\n  title: API\npaths: {}\n",
		},
		{
			name: "replaces existing version",
			in:   "openapi: 3.1.0\ninfo:\n  version: v0.0.1\n  title: API\npaths: {}\n",
			want: "openapi: 3.1.0\ninfo:\n  version: v1.2.3\n  title: API\npaths: {}\n",
		},
		{
			name: "collapses duplicate versions",
			in:   "openapi: 3.1.0\ninfo:\n  version: v1.2.3\n  version: v1.2.3\n  title: API\npaths: {}\n",
			want: "openapi: 3.1.0\ninfo:\n  version: v1.2.3\n  title: API\npaths: {}\n",
		},
		{
			name: "moves version to first field",
			in:   "openapi: 3.1.0\ninfo:\n  title: API\n  version: v0.0.1\npaths: {}\n",
			want: "openapi: 3.1.0\ninfo:\n  version: v1.2.3\n  title: API\npaths: {}\n",
		},
		{
			name: "only touches version under info",
			in:   "openapi: 3.1.0\ninfo:\n  title: API\ncomponents:\n  schemas:\n    Thing:\n      version: keep-me\n",
			want: "openapi: 3.1.0\ninfo:\n  version: v1.2.3\n  title: API\ncomponents:\n  schemas:\n    Thing:\n      version: keep-me\n",
		},
		{
			name: "no info block leaves document unchanged",
			in:   "openapi: 3.1.0\npaths: {}\n",
			want: "openapi: 3.1.0\npaths: {}\n",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := string(setInfoVersion([]byte(tc.in), version))
			if got != tc.want {
				t.Errorf("setInfoVersion() mismatch\n got: %q\nwant: %q", got, tc.want)
			}

			// The transformation must be idempotent: applying it again is a no-op.
			if again := string(setInfoVersion([]byte(got), version)); again != got {
				t.Errorf("setInfoVersion() not idempotent\nfirst:  %q\nsecond: %q", got, again)
			}
		})
	}
}
