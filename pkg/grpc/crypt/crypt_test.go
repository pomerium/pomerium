package crypt

import (
	"bytes"
	"testing"

	"github.com/rs/zerolog"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestZerolog(t *testing.T) {
	var buf bytes.Buffer
	log := zerolog.New(&buf)
	log.Info().EmbedObject(&SealedMessage{
		KeyId:             "KEY_ID",
		DataEncryptionKey: []byte("DATA_ENCRYPTION_KEY"),
		MessageType:       "MESSAGE_TYPE",
		EncryptedMessage:  []byte("ENCRYPTED_MESSAGE"),
	}).Msg("TEST")

	var msg SealedMessage
	err := msg.UnmarshalFromRawZerolog(buf.Bytes())
	require.NoError(t, err)
	assert.Equal(t, "KEY_ID", msg.GetKeyId())
	assert.Equal(t, []byte("DATA_ENCRYPTION_KEY"), msg.GetDataEncryptionKey())
	assert.Equal(t, "MESSAGE_TYPE", msg.GetMessageType())
	assert.Equal(t, []byte("ENCRYPTED_MESSAGE"), msg.GetEncryptedMessage())
}
