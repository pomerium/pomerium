package jsonutil

import "encoding/json"

// MustParse parses data into the given type. It panics if there is an error.
func MustParse[T any](data []byte) T {
	var obj T
	err := json.Unmarshal(data, &obj)
	if err != nil {
		panic(err)
	}
	return obj
}
