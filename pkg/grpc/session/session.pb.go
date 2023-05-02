// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.30.0
// 	protoc        v3.21.7
// source: session.proto

package session

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	emptypb "google.golang.org/protobuf/types/known/emptypb"
	structpb "google.golang.org/protobuf/types/known/structpb"
	timestamppb "google.golang.org/protobuf/types/known/timestamppb"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type IDToken struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Issuer    string                 `protobuf:"bytes,1,opt,name=issuer,proto3" json:"issuer,omitempty"`
	Subject   string                 `protobuf:"bytes,2,opt,name=subject,proto3" json:"subject,omitempty"`
	ExpiresAt *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=expires_at,json=expiresAt,proto3" json:"expires_at,omitempty"`
	IssuedAt  *timestamppb.Timestamp `protobuf:"bytes,4,opt,name=issued_at,json=issuedAt,proto3" json:"issued_at,omitempty"`
	Raw       string                 `protobuf:"bytes,5,opt,name=raw,proto3" json:"raw,omitempty"`
}

func (x *IDToken) Reset() {
	*x = IDToken{}
	if protoimpl.UnsafeEnabled {
		mi := &file_session_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *IDToken) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*IDToken) ProtoMessage() {}

func (x *IDToken) ProtoReflect() protoreflect.Message {
	mi := &file_session_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use IDToken.ProtoReflect.Descriptor instead.
func (*IDToken) Descriptor() ([]byte, []int) {
	return file_session_proto_rawDescGZIP(), []int{0}
}

func (x *IDToken) GetIssuer() string {
	if x != nil {
		return x.Issuer
	}
	return ""
}

func (x *IDToken) GetSubject() string {
	if x != nil {
		return x.Subject
	}
	return ""
}

func (x *IDToken) GetExpiresAt() *timestamppb.Timestamp {
	if x != nil {
		return x.ExpiresAt
	}
	return nil
}

func (x *IDToken) GetIssuedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.IssuedAt
	}
	return nil
}

func (x *IDToken) GetRaw() string {
	if x != nil {
		return x.Raw
	}
	return ""
}

type OAuthToken struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AccessToken  string                 `protobuf:"bytes,1,opt,name=access_token,json=accessToken,proto3" json:"access_token,omitempty"`
	TokenType    string                 `protobuf:"bytes,2,opt,name=token_type,json=tokenType,proto3" json:"token_type,omitempty"`
	ExpiresAt    *timestamppb.Timestamp `protobuf:"bytes,3,opt,name=expires_at,json=expiresAt,proto3" json:"expires_at,omitempty"`
	RefreshToken string                 `protobuf:"bytes,4,opt,name=refresh_token,json=refreshToken,proto3" json:"refresh_token,omitempty"`
}

func (x *OAuthToken) Reset() {
	*x = OAuthToken{}
	if protoimpl.UnsafeEnabled {
		mi := &file_session_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *OAuthToken) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*OAuthToken) ProtoMessage() {}

func (x *OAuthToken) ProtoReflect() protoreflect.Message {
	mi := &file_session_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use OAuthToken.ProtoReflect.Descriptor instead.
func (*OAuthToken) Descriptor() ([]byte, []int) {
	return file_session_proto_rawDescGZIP(), []int{1}
}

func (x *OAuthToken) GetAccessToken() string {
	if x != nil {
		return x.AccessToken
	}
	return ""
}

func (x *OAuthToken) GetTokenType() string {
	if x != nil {
		return x.TokenType
	}
	return ""
}

func (x *OAuthToken) GetExpiresAt() *timestamppb.Timestamp {
	if x != nil {
		return x.ExpiresAt
	}
	return nil
}

func (x *OAuthToken) GetRefreshToken() string {
	if x != nil {
		return x.RefreshToken
	}
	return ""
}

type Session struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Version              string                         `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
	Id                   string                         `protobuf:"bytes,2,opt,name=id,proto3" json:"id,omitempty"`
	UserId               string                         `protobuf:"bytes,3,opt,name=user_id,json=userId,proto3" json:"user_id,omitempty"`
	DeviceCredentials    []*Session_DeviceCredential    `protobuf:"bytes,17,rep,name=device_credentials,json=deviceCredentials,proto3" json:"device_credentials,omitempty"`
	IssuedAt             *timestamppb.Timestamp         `protobuf:"bytes,14,opt,name=issued_at,json=issuedAt,proto3" json:"issued_at,omitempty"`
	ExpiresAt            *timestamppb.Timestamp         `protobuf:"bytes,4,opt,name=expires_at,json=expiresAt,proto3" json:"expires_at,omitempty"`
	AccessedAt           *timestamppb.Timestamp         `protobuf:"bytes,18,opt,name=accessed_at,json=accessedAt,proto3" json:"accessed_at,omitempty"`
	IdToken              *IDToken                       `protobuf:"bytes,6,opt,name=id_token,json=idToken,proto3" json:"id_token,omitempty"`
	OauthToken           *OAuthToken                    `protobuf:"bytes,7,opt,name=oauth_token,json=oauthToken,proto3" json:"oauth_token,omitempty"`
	Claims               map[string]*structpb.ListValue `protobuf:"bytes,9,rep,name=claims,proto3" json:"claims,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	Audience             []string                       `protobuf:"bytes,10,rep,name=audience,proto3" json:"audience,omitempty"`
	ImpersonateSessionId *string                        `protobuf:"bytes,15,opt,name=impersonate_session_id,json=impersonateSessionId,proto3,oneof" json:"impersonate_session_id,omitempty"`
}

func (x *Session) Reset() {
	*x = Session{}
	if protoimpl.UnsafeEnabled {
		mi := &file_session_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Session) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Session) ProtoMessage() {}

func (x *Session) ProtoReflect() protoreflect.Message {
	mi := &file_session_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Session.ProtoReflect.Descriptor instead.
func (*Session) Descriptor() ([]byte, []int) {
	return file_session_proto_rawDescGZIP(), []int{2}
}

func (x *Session) GetVersion() string {
	if x != nil {
		return x.Version
	}
	return ""
}

func (x *Session) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Session) GetUserId() string {
	if x != nil {
		return x.UserId
	}
	return ""
}

func (x *Session) GetDeviceCredentials() []*Session_DeviceCredential {
	if x != nil {
		return x.DeviceCredentials
	}
	return nil
}

func (x *Session) GetIssuedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.IssuedAt
	}
	return nil
}

func (x *Session) GetExpiresAt() *timestamppb.Timestamp {
	if x != nil {
		return x.ExpiresAt
	}
	return nil
}

func (x *Session) GetAccessedAt() *timestamppb.Timestamp {
	if x != nil {
		return x.AccessedAt
	}
	return nil
}

func (x *Session) GetIdToken() *IDToken {
	if x != nil {
		return x.IdToken
	}
	return nil
}

func (x *Session) GetOauthToken() *OAuthToken {
	if x != nil {
		return x.OauthToken
	}
	return nil
}

func (x *Session) GetClaims() map[string]*structpb.ListValue {
	if x != nil {
		return x.Claims
	}
	return nil
}

func (x *Session) GetAudience() []string {
	if x != nil {
		return x.Audience
	}
	return nil
}

func (x *Session) GetImpersonateSessionId() string {
	if x != nil && x.ImpersonateSessionId != nil {
		return *x.ImpersonateSessionId
	}
	return ""
}

type Session_DeviceCredential struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	TypeId string `protobuf:"bytes,1,opt,name=type_id,json=typeId,proto3" json:"type_id,omitempty"`
	// Types that are assignable to Credential:
	//
	//	*Session_DeviceCredential_Unavailable
	//	*Session_DeviceCredential_Id
	Credential isSession_DeviceCredential_Credential `protobuf_oneof:"credential"`
}

func (x *Session_DeviceCredential) Reset() {
	*x = Session_DeviceCredential{}
	if protoimpl.UnsafeEnabled {
		mi := &file_session_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Session_DeviceCredential) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Session_DeviceCredential) ProtoMessage() {}

func (x *Session_DeviceCredential) ProtoReflect() protoreflect.Message {
	mi := &file_session_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Session_DeviceCredential.ProtoReflect.Descriptor instead.
func (*Session_DeviceCredential) Descriptor() ([]byte, []int) {
	return file_session_proto_rawDescGZIP(), []int{2, 0}
}

func (x *Session_DeviceCredential) GetTypeId() string {
	if x != nil {
		return x.TypeId
	}
	return ""
}

func (m *Session_DeviceCredential) GetCredential() isSession_DeviceCredential_Credential {
	if m != nil {
		return m.Credential
	}
	return nil
}

func (x *Session_DeviceCredential) GetUnavailable() *emptypb.Empty {
	if x, ok := x.GetCredential().(*Session_DeviceCredential_Unavailable); ok {
		return x.Unavailable
	}
	return nil
}

func (x *Session_DeviceCredential) GetId() string {
	if x, ok := x.GetCredential().(*Session_DeviceCredential_Id); ok {
		return x.Id
	}
	return ""
}

type isSession_DeviceCredential_Credential interface {
	isSession_DeviceCredential_Credential()
}

type Session_DeviceCredential_Unavailable struct {
	Unavailable *emptypb.Empty `protobuf:"bytes,2,opt,name=unavailable,proto3,oneof"`
}

type Session_DeviceCredential_Id struct {
	Id string `protobuf:"bytes,3,opt,name=id,proto3,oneof"`
}

func (*Session_DeviceCredential_Unavailable) isSession_DeviceCredential_Credential() {}

func (*Session_DeviceCredential_Id) isSession_DeviceCredential_Credential() {}

var File_session_proto protoreflect.FileDescriptor

var file_session_proto_rawDesc = []byte{
	0x0a, 0x0d, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12,
	0x07, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x1a, 0x1b, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x65, 0x6d, 0x70, 0x74, 0x79, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2f, 0x73, 0x74, 0x72, 0x75, 0x63, 0x74, 0x2e, 0x70, 0x72,
	0x6f, 0x74, 0x6f, 0x1a, 0x1f, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x62, 0x75, 0x66, 0x2f, 0x74, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x22, 0xc1, 0x01, 0x0a, 0x07, 0x49, 0x44, 0x54, 0x6f, 0x6b, 0x65, 0x6e,
	0x12, 0x16, 0x0a, 0x06, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x06, 0x69, 0x73, 0x73, 0x75, 0x65, 0x72, 0x12, 0x18, 0x0a, 0x07, 0x73, 0x75, 0x62, 0x6a,
	0x65, 0x63, 0x74, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x73, 0x75, 0x62, 0x6a, 0x65,
	0x63, 0x74, 0x12, 0x39, 0x0a, 0x0a, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x5f, 0x61, 0x74,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e,
	0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61,
	0x6d, 0x70, 0x52, 0x09, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x41, 0x74, 0x12, 0x37, 0x0a,
	0x09, 0x69, 0x73, 0x73, 0x75, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b,
	0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62,
	0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x08, 0x69, 0x73,
	0x73, 0x75, 0x65, 0x64, 0x41, 0x74, 0x12, 0x10, 0x0a, 0x03, 0x72, 0x61, 0x77, 0x18, 0x05, 0x20,
	0x01, 0x28, 0x09, 0x52, 0x03, 0x72, 0x61, 0x77, 0x22, 0xae, 0x01, 0x0a, 0x0a, 0x4f, 0x41, 0x75,
	0x74, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x21, 0x0a, 0x0c, 0x61, 0x63, 0x63, 0x65, 0x73,
	0x73, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0b, 0x61,
	0x63, 0x63, 0x65, 0x73, 0x73, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x1d, 0x0a, 0x0a, 0x74, 0x6f,
	0x6b, 0x65, 0x6e, 0x5f, 0x74, 0x79, 0x70, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x09,
	0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x54, 0x79, 0x70, 0x65, 0x12, 0x39, 0x0a, 0x0a, 0x65, 0x78, 0x70,
	0x69, 0x72, 0x65, 0x73, 0x5f, 0x61, 0x74, 0x18, 0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x09, 0x65, 0x78, 0x70, 0x69, 0x72,
	0x65, 0x73, 0x41, 0x74, 0x12, 0x23, 0x0a, 0x0d, 0x72, 0x65, 0x66, 0x72, 0x65, 0x73, 0x68, 0x5f,
	0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x04, 0x20, 0x01, 0x28, 0x09, 0x52, 0x0c, 0x72, 0x65, 0x66,
	0x72, 0x65, 0x73, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x22, 0xbb, 0x06, 0x0a, 0x07, 0x53, 0x65,
	0x73, 0x73, 0x69, 0x6f, 0x6e, 0x12, 0x18, 0x0a, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x76, 0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x12,
	0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x02, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x12,
	0x17, 0x0a, 0x07, 0x75, 0x73, 0x65, 0x72, 0x5f, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x06, 0x75, 0x73, 0x65, 0x72, 0x49, 0x64, 0x12, 0x50, 0x0a, 0x12, 0x64, 0x65, 0x76, 0x69,
	0x63, 0x65, 0x5f, 0x63, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x18, 0x11,
	0x20, 0x03, 0x28, 0x0b, 0x32, 0x21, 0x2e, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x53,
	0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x43, 0x72, 0x65,
	0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x52, 0x11, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x43,
	0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c, 0x73, 0x12, 0x37, 0x0a, 0x09, 0x69, 0x73,
	0x73, 0x75, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x0e, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e,
	0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e,
	0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52, 0x08, 0x69, 0x73, 0x73, 0x75, 0x65,
	0x64, 0x41, 0x74, 0x12, 0x39, 0x0a, 0x0a, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x5f, 0x61,
	0x74, 0x18, 0x04, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65,
	0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74,
	0x61, 0x6d, 0x70, 0x52, 0x09, 0x65, 0x78, 0x70, 0x69, 0x72, 0x65, 0x73, 0x41, 0x74, 0x12, 0x3b,
	0x0a, 0x0b, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x65, 0x64, 0x5f, 0x61, 0x74, 0x18, 0x12, 0x20,
	0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x54, 0x69, 0x6d, 0x65, 0x73, 0x74, 0x61, 0x6d, 0x70, 0x52,
	0x0a, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x65, 0x64, 0x41, 0x74, 0x12, 0x2b, 0x0a, 0x08, 0x69,
	0x64, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x06, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x10, 0x2e,
	0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x49, 0x44, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x52,
	0x07, 0x69, 0x64, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x34, 0x0a, 0x0b, 0x6f, 0x61, 0x75, 0x74,
	0x68, 0x5f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x18, 0x07, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x13, 0x2e,
	0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x4f, 0x41, 0x75, 0x74, 0x68, 0x54, 0x6f, 0x6b,
	0x65, 0x6e, 0x52, 0x0a, 0x6f, 0x61, 0x75, 0x74, 0x68, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x34,
	0x0a, 0x06, 0x63, 0x6c, 0x61, 0x69, 0x6d, 0x73, 0x18, 0x09, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x1c,
	0x2e, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x2e, 0x53, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e,
	0x2e, 0x43, 0x6c, 0x61, 0x69, 0x6d, 0x73, 0x45, 0x6e, 0x74, 0x72, 0x79, 0x52, 0x06, 0x63, 0x6c,
	0x61, 0x69, 0x6d, 0x73, 0x12, 0x1a, 0x0a, 0x08, 0x61, 0x75, 0x64, 0x69, 0x65, 0x6e, 0x63, 0x65,
	0x18, 0x0a, 0x20, 0x03, 0x28, 0x09, 0x52, 0x08, 0x61, 0x75, 0x64, 0x69, 0x65, 0x6e, 0x63, 0x65,
	0x12, 0x39, 0x0a, 0x16, 0x69, 0x6d, 0x70, 0x65, 0x72, 0x73, 0x6f, 0x6e, 0x61, 0x74, 0x65, 0x5f,
	0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x18, 0x0f, 0x20, 0x01, 0x28, 0x09,
	0x48, 0x00, 0x52, 0x14, 0x69, 0x6d, 0x70, 0x65, 0x72, 0x73, 0x6f, 0x6e, 0x61, 0x74, 0x65, 0x53,
	0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x49, 0x64, 0x88, 0x01, 0x01, 0x1a, 0x87, 0x01, 0x0a, 0x10,
	0x44, 0x65, 0x76, 0x69, 0x63, 0x65, 0x43, 0x72, 0x65, 0x64, 0x65, 0x6e, 0x74, 0x69, 0x61, 0x6c,
	0x12, 0x17, 0x0a, 0x07, 0x74, 0x79, 0x70, 0x65, 0x5f, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x06, 0x74, 0x79, 0x70, 0x65, 0x49, 0x64, 0x12, 0x3a, 0x0a, 0x0b, 0x75, 0x6e, 0x61,
	0x76, 0x61, 0x69, 0x6c, 0x61, 0x62, 0x6c, 0x65, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x16,
	0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66,
	0x2e, 0x45, 0x6d, 0x70, 0x74, 0x79, 0x48, 0x00, 0x52, 0x0b, 0x75, 0x6e, 0x61, 0x76, 0x61, 0x69,
	0x6c, 0x61, 0x62, 0x6c, 0x65, 0x12, 0x10, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x03, 0x20, 0x01, 0x28,
	0x09, 0x48, 0x00, 0x52, 0x02, 0x69, 0x64, 0x42, 0x0c, 0x0a, 0x0a, 0x63, 0x72, 0x65, 0x64, 0x65,
	0x6e, 0x74, 0x69, 0x61, 0x6c, 0x1a, 0x55, 0x0a, 0x0b, 0x43, 0x6c, 0x61, 0x69, 0x6d, 0x73, 0x45,
	0x6e, 0x74, 0x72, 0x79, 0x12, 0x10, 0x0a, 0x03, 0x6b, 0x65, 0x79, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x09, 0x52, 0x03, 0x6b, 0x65, 0x79, 0x12, 0x30, 0x0a, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x18,
	0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x1a, 0x2e, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x62, 0x75, 0x66, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x56, 0x61, 0x6c, 0x75,
	0x65, 0x52, 0x05, 0x76, 0x61, 0x6c, 0x75, 0x65, 0x3a, 0x02, 0x38, 0x01, 0x42, 0x19, 0x0a, 0x17,
	0x5f, 0x69, 0x6d, 0x70, 0x65, 0x72, 0x73, 0x6f, 0x6e, 0x61, 0x74, 0x65, 0x5f, 0x73, 0x65, 0x73,
	0x73, 0x69, 0x6f, 0x6e, 0x5f, 0x69, 0x64, 0x42, 0x2f, 0x5a, 0x2d, 0x67, 0x69, 0x74, 0x68, 0x75,
	0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2f, 0x70,
	0x6f, 0x6d, 0x65, 0x72, 0x69, 0x75, 0x6d, 0x2f, 0x70, 0x6b, 0x67, 0x2f, 0x67, 0x72, 0x70, 0x63,
	0x2f, 0x73, 0x65, 0x73, 0x73, 0x69, 0x6f, 0x6e, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_session_proto_rawDescOnce sync.Once
	file_session_proto_rawDescData = file_session_proto_rawDesc
)

func file_session_proto_rawDescGZIP() []byte {
	file_session_proto_rawDescOnce.Do(func() {
		file_session_proto_rawDescData = protoimpl.X.CompressGZIP(file_session_proto_rawDescData)
	})
	return file_session_proto_rawDescData
}

var file_session_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_session_proto_goTypes = []interface{}{
	(*IDToken)(nil),                  // 0: session.IDToken
	(*OAuthToken)(nil),               // 1: session.OAuthToken
	(*Session)(nil),                  // 2: session.Session
	(*Session_DeviceCredential)(nil), // 3: session.Session.DeviceCredential
	nil,                              // 4: session.Session.ClaimsEntry
	(*timestamppb.Timestamp)(nil),    // 5: google.protobuf.Timestamp
	(*emptypb.Empty)(nil),            // 6: google.protobuf.Empty
	(*structpb.ListValue)(nil),       // 7: google.protobuf.ListValue
}
var file_session_proto_depIdxs = []int32{
	5,  // 0: session.IDToken.expires_at:type_name -> google.protobuf.Timestamp
	5,  // 1: session.IDToken.issued_at:type_name -> google.protobuf.Timestamp
	5,  // 2: session.OAuthToken.expires_at:type_name -> google.protobuf.Timestamp
	3,  // 3: session.Session.device_credentials:type_name -> session.Session.DeviceCredential
	5,  // 4: session.Session.issued_at:type_name -> google.protobuf.Timestamp
	5,  // 5: session.Session.expires_at:type_name -> google.protobuf.Timestamp
	5,  // 6: session.Session.accessed_at:type_name -> google.protobuf.Timestamp
	0,  // 7: session.Session.id_token:type_name -> session.IDToken
	1,  // 8: session.Session.oauth_token:type_name -> session.OAuthToken
	4,  // 9: session.Session.claims:type_name -> session.Session.ClaimsEntry
	6,  // 10: session.Session.DeviceCredential.unavailable:type_name -> google.protobuf.Empty
	7,  // 11: session.Session.ClaimsEntry.value:type_name -> google.protobuf.ListValue
	12, // [12:12] is the sub-list for method output_type
	12, // [12:12] is the sub-list for method input_type
	12, // [12:12] is the sub-list for extension type_name
	12, // [12:12] is the sub-list for extension extendee
	0,  // [0:12] is the sub-list for field type_name
}

func init() { file_session_proto_init() }
func file_session_proto_init() {
	if File_session_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_session_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*IDToken); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_session_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*OAuthToken); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_session_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Session); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_session_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*Session_DeviceCredential); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_session_proto_msgTypes[2].OneofWrappers = []interface{}{}
	file_session_proto_msgTypes[3].OneofWrappers = []interface{}{
		(*Session_DeviceCredential_Unavailable)(nil),
		(*Session_DeviceCredential_Id)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_session_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_session_proto_goTypes,
		DependencyIndexes: file_session_proto_depIdxs,
		MessageInfos:      file_session_proto_msgTypes,
	}.Build()
	File_session_proto = out.File
	file_session_proto_rawDesc = nil
	file_session_proto_goTypes = nil
	file_session_proto_depIdxs = nil
}
