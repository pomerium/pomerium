package xslice

import (
	"errors"
	"fmt"
	"strings"
)

var (
	// errAlreadySet returned if values set once.
	errAlreadySet = errors.New("already set")
)

// CommaSlice is a slice that supports comma seperated strings
// to be set to itself.
type CommaSlice []string

// String returns a string representation of slice.
func (s *CommaSlice) String() string {
	return fmt.Sprint(*s)
}

// Set sets comma seperated values to slice.
func (s *CommaSlice) Set(value string) error {
	if len(*s) > 0 {
		return errAlreadySet
	}
	for _, dt := range strings.Split(value, ",") {
		*s = append(*s, dt)
	}
	return nil
}
