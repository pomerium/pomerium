package api

import (
	"errors"
)

var (
	errUsernameMissing      = errors.New("username missing")
	errHostnameMissing      = errors.New("hostname missing")
	errUsernameInconsistent = errors.New("username inconsistent")
	errHostnameInconsistent = errors.New("hostname inconsistent")
)

type UserRequest struct {
	username string
	hostname string
	valid    bool
}

func (u UserRequest) Username() string {
	if !u.valid {
		panic("bug: Username() called on an invalid UserRequest")
	}
	return u.username
}

func (u UserRequest) Hostname() string {
	if !u.valid {
		panic("bug: Hostname() called on an invalid UserRequest")
	}
	return u.hostname
}

func (u UserRequest) Valid() bool {
	return u.valid
}

func (u *UserRequest) SetOrCheckEqual(newUsername, newHostname string) error {
	if newUsername == "" {
		return errUsernameMissing
	}
	if u.valid {
		if u.username != newUsername {
			return errUsernameInconsistent
		}
		if u.hostname != newHostname {
			return errHostnameInconsistent
		}
	}
	u.username = newUsername
	u.hostname = newHostname
	u.valid = true
	return nil
}

func (u *UserRequest) PromoteFrom(other UserRequest) error {
	if u.Hostname() != "" {
		panic("bug: PromoteFrom() called but the current hostname is not empty")
	}
	if u.Username() != other.Username() {
		return errUsernameInconsistent
	}
	if other.Hostname() == "" {
		return errHostnameMissing
	}
	u.hostname = other.Hostname()
	return nil
}

func NewUserRequest(username, hostname string) (u UserRequest, err error) {
	err = u.SetOrCheckEqual(username, hostname)
	return
}
