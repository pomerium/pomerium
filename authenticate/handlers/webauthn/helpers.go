package webauthn

import "github.com/pomerium/pomerium/pkg/grpc/session"

func containsString(elements []string, value string) bool {
	for _, element := range elements {
		if element == value {
			return true
		}
	}
	return false
}

func removeString(elements []string, value string) []string {
	dup := make([]string, 0, len(elements))
	for _, element := range elements {
		if element != value {
			dup = append(dup, element)
		}
	}
	return dup
}

func removeSessionDeviceCredential(elements []*session.Session_DeviceCredential, id string) []*session.Session_DeviceCredential {
	dup := make([]*session.Session_DeviceCredential, 0, len(elements))
	for _, element := range elements {
		if element.GetId() != id {
			dup = append(dup, element)
		}
	}
	return dup
}
