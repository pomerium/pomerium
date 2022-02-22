package webauthnutil

import (
	"github.com/google/uuid"

	"github.com/pomerium/pomerium/pkg/grpc/user"
	"github.com/pomerium/webauthn"
)

var pomeriumUserNamespace = uuid.MustParse("2929d3f7-f0b0-478f-9dd5-970d51eb3859")

// GetUserEntity gets the PublicKeyCredentialUserEntity from a Pomerium user.
func GetUserEntity(pomeriumUser *user.User) webauthn.PublicKeyCredentialUserEntity {
	name := pomeriumUser.GetEmail()
	if name == "" {
		name = pomeriumUser.GetId()
	}
	displayName := pomeriumUser.GetName()
	if displayName == "" {
		displayName = name
	}
	return webauthn.PublicKeyCredentialUserEntity{
		ID:          GetUserEntityID(pomeriumUser.GetId()),
		DisplayName: displayName,
		Name:        name,
	}
}

// GetUserEntityID gets the UserEntity ID.
//
// The WebAuthn spec states:
//
// > The user handle of the user account entity. A user handle is an opaque byte sequence with a maximum size of 64
// > bytes, and is not meant to be displayed to the user.
// >
// > To ensure secure operation, authentication and authorization decisions MUST be made on the basis of this id
// > member, not the displayName nor name members. See Section 6.1 of [RFC8266].
// >
// > The user handle MUST NOT contain personally identifying information about the user, such as a username or e-mail
// > address; see §14.6.1 User Handle Contents for details. The user handle MUST NOT be empty, though it MAY be
// > null.
//
// To meet these requirements we hash the user ID (since it's often an email address in the IdP) using a UUID v5 in a
// custom UUID namespace: 2929d3f7-f0b0-478f-9dd5-970d51eb3859.
func GetUserEntityID(pomeriumUserID string) []byte {
	id := uuid.NewSHA1(pomeriumUserNamespace, []byte(pomeriumUserID))
	return id[:]
}
