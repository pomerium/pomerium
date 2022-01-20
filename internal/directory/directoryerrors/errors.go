// Package directoryerrors contains errors used by directory providers.
package directoryerrors

import "errors"

// ErrPreferExistingInformation indicates that the information returned by the provider should
// only be used if a record is brand new, otherwise the existing information should be kept as is.
var ErrPreferExistingInformation = errors.New("user ignored")
