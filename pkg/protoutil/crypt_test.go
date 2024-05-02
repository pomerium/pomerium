package protoutil

import (
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/pomerium/pomerium/pkg/cryptutil"
)

func TestEncryptor_Encrypt(t *testing.T) {
	t.Run("simple", func(t *testing.T) {
		kek, err := cryptutil.GenerateKeyEncryptionKey()
		require.NoError(t, err)
		enc := NewEncryptor(kek.Public())
		sealed, err := enc.Encrypt(wrapperspb.String("HELLO WORLD"))
		require.NoError(t, err)
		require.Equal(t, kek.Public().ID(), sealed.GetKeyId())
		require.NotEmpty(t, sealed.GetDataEncryptionKey())
		require.Equal(t, "type.googleapis.com/google.protobuf.StringValue", sealed.GetMessageType())
		require.NotEmpty(t, sealed.GetEncryptedMessage())
	})

	t.Run("reuse dek", func(t *testing.T) {
		kek, err := cryptutil.GenerateKeyEncryptionKey()
		require.NoError(t, err)
		enc := NewEncryptor(kek.Public())
		s1, err := enc.Encrypt(wrapperspb.String("HELLO WORLD"))
		require.NoError(t, err)
		s2, err := enc.Encrypt(wrapperspb.String("HELLO WORLD"))
		require.NoError(t, err)
		assert.Equal(t, s1.GetDataEncryptionKey(), s2.GetDataEncryptionKey())
	})
	t.Run("rotate dek", func(t *testing.T) {
		kek, err := cryptutil.GenerateKeyEncryptionKey()
		require.NoError(t, err)
		enc := NewEncryptor(kek.Public())
		s1, err := enc.Encrypt(wrapperspb.String("HELLO WORLD"))
		require.NoError(t, err)
		enc.nextRotate = time.Now()
		s2, err := enc.Encrypt(wrapperspb.String("HELLO WORLD"))
		require.NoError(t, err)
		assert.NotEqual(t, s1.GetDataEncryptionKey(), s2.GetDataEncryptionKey())
	})
}

func TestDecryptor_Decrypt(t *testing.T) {
	expect := wrapperspb.String("HELLO WORLD")

	kek, err := cryptutil.GenerateKeyEncryptionKey()
	require.NoError(t, err)

	enc := NewEncryptor(kek.Public())
	sealed, err := enc.Encrypt(expect)
	require.NoError(t, err)

	dec := NewDecryptor(cryptutil.KeyEncryptionKeySourceFunc(func(id string) (*cryptutil.PrivateKeyEncryptionKey, error) {
		require.Equal(t, kek.ID(), id)
		return kek, nil
	}))
	opened, err := dec.Decrypt(sealed)
	require.NoError(t, err)
	assertProtoEqual(t, expect, opened)
}

func assertProtoEqual(t *testing.T, x, y proto.Message) {
	xbs, _ := protojson.Marshal(x)
	ybs, _ := protojson.Marshal(y)
	assert.True(t, proto.Equal(x, y), "%s != %s", xbs, ybs)
}

func BenchmarkEncrypt(b *testing.B) {
	m := map[string]any{}
	for i := 0; i < 10; i++ {
		mm := map[string]any{}
		for j := 0; j < 10; j++ {
			mm[fmt.Sprintf("key%d", j)] = fmt.Sprintf("value%d", j)
		}
		m[fmt.Sprintf("key%d", i)] = mm
	}

	obj, err := structpb.NewStruct(m)
	require.NoError(b, err)

	kek, err := cryptutil.GenerateKeyEncryptionKey()
	require.NoError(b, err)
	enc := NewEncryptor(kek.Public())

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := enc.Encrypt(obj)
		require.NoError(b, err)
	}
}
