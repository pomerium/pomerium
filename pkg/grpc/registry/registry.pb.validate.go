// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: registry.proto

package registry

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang/protobuf/ptypes"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = ptypes.DynamicAny{}
)

// define the regex for a UUID once up-front
var _registry_uuidPattern = regexp.MustCompile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

// Validate checks the field values on Service with the rules defined in the
// proto definition for this message. If any rules are violated, an error is returned.
func (m *Service) Validate() error {
	if m == nil {
		return nil
	}

	if _, ok := _Service_Kind_NotInLookup[m.GetKind()]; ok {
		return ServiceValidationError{
			field:  "Kind",
			reason: "value must not be in list [0]",
		}
	}

	if uri, err := url.Parse(m.GetEndpoint()); err != nil {
		return ServiceValidationError{
			field:  "Endpoint",
			reason: "value must be a valid URI",
			cause:  err,
		}
	} else if !uri.IsAbs() {
		return ServiceValidationError{
			field:  "Endpoint",
			reason: "value must be absolute",
		}
	}

	return nil
}

// ServiceValidationError is the validation error returned by Service.Validate
// if the designated constraints aren't met.
type ServiceValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ServiceValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ServiceValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ServiceValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ServiceValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ServiceValidationError) ErrorName() string { return "ServiceValidationError" }

// Error satisfies the builtin error interface
func (e ServiceValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sService.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ServiceValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ServiceValidationError{}

var _Service_Kind_NotInLookup = map[ServiceKind]struct{}{
	0: {},
}

// Validate checks the field values on RegisterRequest with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned.
func (m *RegisterRequest) Validate() error {
	if m == nil {
		return nil
	}

	if len(m.GetServices()) < 1 {
		return RegisterRequestValidationError{
			field:  "Services",
			reason: "value must contain at least 1 item(s)",
		}
	}

	for idx, item := range m.GetServices() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return RegisterRequestValidationError{
					field:  fmt.Sprintf("Services[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	for key, val := range m.GetMetadata() {
		_ = val

		// no validation rules for Metadata[key]

		if v, ok := interface{}(val).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return RegisterRequestValidationError{
					field:  fmt.Sprintf("Metadata[%v]", key),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	return nil
}

// RegisterRequestValidationError is the validation error returned by
// RegisterRequest.Validate if the designated constraints aren't met.
type RegisterRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e RegisterRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e RegisterRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e RegisterRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e RegisterRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e RegisterRequestValidationError) ErrorName() string { return "RegisterRequestValidationError" }

// Error satisfies the builtin error interface
func (e RegisterRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRegisterRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = RegisterRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = RegisterRequestValidationError{}

// Validate checks the field values on RegisterResponse with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned.
func (m *RegisterResponse) Validate() error {
	if m == nil {
		return nil
	}

	if v, ok := interface{}(m.GetCallBackAfter()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return RegisterResponseValidationError{
				field:  "CallBackAfter",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	return nil
}

// RegisterResponseValidationError is the validation error returned by
// RegisterResponse.Validate if the designated constraints aren't met.
type RegisterResponseValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e RegisterResponseValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e RegisterResponseValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e RegisterResponseValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e RegisterResponseValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e RegisterResponseValidationError) ErrorName() string { return "RegisterResponseValidationError" }

// Error satisfies the builtin error interface
func (e RegisterResponseValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sRegisterResponse.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = RegisterResponseValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = RegisterResponseValidationError{}

// Validate checks the field values on ListRequest with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *ListRequest) Validate() error {
	if m == nil {
		return nil
	}

	return nil
}

// ListRequestValidationError is the validation error returned by
// ListRequest.Validate if the designated constraints aren't met.
type ListRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ListRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ListRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ListRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ListRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ListRequestValidationError) ErrorName() string { return "ListRequestValidationError" }

// Error satisfies the builtin error interface
func (e ListRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sListRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ListRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ListRequestValidationError{}

// Validate checks the field values on ServiceRegistration with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *ServiceRegistration) Validate() error {
	if m == nil {
		return nil
	}

	if v, ok := interface{}(m.GetService()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ServiceRegistrationValidationError{
				field:  "Service",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetExpiresAt()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return ServiceRegistrationValidationError{
				field:  "ExpiresAt",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	return nil
}

// ServiceRegistrationValidationError is the validation error returned by
// ServiceRegistration.Validate if the designated constraints aren't met.
type ServiceRegistrationValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ServiceRegistrationValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ServiceRegistrationValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ServiceRegistrationValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ServiceRegistrationValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ServiceRegistrationValidationError) ErrorName() string {
	return "ServiceRegistrationValidationError"
}

// Error satisfies the builtin error interface
func (e ServiceRegistrationValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sServiceRegistration.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ServiceRegistrationValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ServiceRegistrationValidationError{}

// Validate checks the field values on ServiceList with the rules defined in
// the proto definition for this message. If any rules are violated, an error
// is returned.
func (m *ServiceList) Validate() error {
	if m == nil {
		return nil
	}

	for idx, item := range m.GetServices() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return ServiceListValidationError{
					field:  fmt.Sprintf("Services[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	return nil
}

// ServiceListValidationError is the validation error returned by
// ServiceList.Validate if the designated constraints aren't met.
type ServiceListValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ServiceListValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ServiceListValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ServiceListValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ServiceListValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ServiceListValidationError) ErrorName() string { return "ServiceListValidationError" }

// Error satisfies the builtin error interface
func (e ServiceListValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sServiceList.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ServiceListValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ServiceListValidationError{}
