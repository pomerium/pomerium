package envoy

import (
	"io/ioutil"
	"strconv"
)

const baseIDPath = "/tmp/pomerium-envoy-base-id"

func firstNonEmpty(args ...string) string {
	for _, a := range args {
		if a != "" {
			return a
		}
	}
	return ""
}

func readBaseID() (int, bool) {
	bs, err := ioutil.ReadFile(baseIDPath)
	if err != nil {
		return 0, false
	}

	baseID, err := strconv.Atoi(string(bs))
	if err != nil {
		return 0, false
	}

	return baseID, true
}
