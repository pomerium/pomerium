package protoutil

import (
	"fmt"
	"sync"
	"time"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/pomerium/pomerium/pkg/cryptutil"
	cryptpb "github.com/pomerium/pomerium/pkg/grpc/crypt"
)

// An Encryptor encrypts protobuf messages using a key encryption key and periodically rotated
// generated data encryption keys.
type Encryptor struct {
	kek         *cryptutil.PublicKeyEncryptionKey
	rotateEvery time.Duration

	sync.RWMutex
	nextRotate   time.Time
	dek          *cryptutil.DataEncryptionKey
	encryptedDEK []byte
}

// NewEncryptor returns a new protobuf Encryptor.
func NewEncryptor(kek *cryptutil.PublicKeyEncryptionKey) *Encryptor {
	return &Encryptor{
		kek:         kek,
		rotateEvery: time.Hour,
	}
}

func (enc *Encryptor) getDataEncryptionKey() (*cryptutil.DataEncryptionKey, []byte, error) {
	// double-checked locking
	// first time we do a read only lookup
	enc.RLock()
	dek, encryptedDEK, err := enc.getDataEncryptionKeyLocked(true)
	enc.RUnlock()
	if err != nil {
		return nil, nil, err
	} else if dek != nil {
		return dek, encryptedDEK, nil
	}

	// second time we do a read/write lookup
	enc.Lock()
	dek, encryptedDEK, err = enc.getDataEncryptionKeyLocked(false)
	enc.Unlock()
	return dek, encryptedDEK, err
}

func (enc *Encryptor) getDataEncryptionKeyLocked(readOnly bool) (*cryptutil.DataEncryptionKey, []byte, error) {
	needsNewKey := enc.dek == nil || time.Now().After(enc.nextRotate)
	if !needsNewKey {
		return enc.dek, enc.encryptedDEK, nil
	}

	if readOnly {
		return nil, nil, nil
	}

	// generate a new data encryption key
	dek, err := cryptutil.GenerateDataEncryptionKey()
	if err != nil {
		return nil, nil, err
	}

	// seal the data encryption key using the key encryption key
	encryptedDEK, err := enc.kek.EncryptDataEncryptionKey(dek)
	if err != nil {
		return nil, nil, err
	}

	enc.dek = dek
	enc.encryptedDEK = encryptedDEK
	enc.nextRotate = time.Now().Add(enc.rotateEvery)

	return enc.dek, enc.encryptedDEK, nil
}

// Encrypt encrypts a protobuf message.
func (enc *Encryptor) Encrypt(msg proto.Message) (*cryptpb.SealedMessage, error) {
	// get the data encryption key
	dek, encryptedDEK, err := enc.getDataEncryptionKey()
	if err != nil {
		return nil, err
	}

	plaintext, err := protojson.Marshal(msg)
	if err != nil {
		return nil, err
	}
	ciphertext := dek.Encrypt(plaintext)

	return &cryptpb.SealedMessage{
		KeyId:             enc.kek.ID(),
		DataEncryptionKey: encryptedDEK,
		MessageType:       GetTypeURL(msg),
		EncryptedMessage:  ciphertext,
	}, nil
}

// A Decryptor decrypts encrypted protobuf messages.
type Decryptor struct {
	keySource cryptutil.KeyEncryptionKeySource
	dekCache  *cryptutil.DataEncryptionKeyCache
}

// NewDecryptor creates a new decryptor.
func NewDecryptor(keySource cryptutil.KeyEncryptionKeySource) *Decryptor {
	return &Decryptor{
		keySource: keySource,
		dekCache:  cryptutil.NewDataEncryptionKeyCache(),
	}
}

func (dec *Decryptor) getDataEncryptionKey(keyEncryptionKeyID string, encryptedDEK []byte) (*cryptutil.DataEncryptionKey, error) {
	// return a dek if its already cached
	dek, ok := dec.dekCache.Get(encryptedDEK)
	if ok {
		return dek, nil
	}

	// look up the kek used for this dek
	kek, err := dec.keySource.GetKeyEncryptionKey(keyEncryptionKeyID)
	if err != nil {
		return nil, fmt.Errorf("protoutil: error getting key-encryption-key (%s): %w",
			keyEncryptionKeyID, err)
	}

	// decrypt the dek via the private kek
	dek, err = kek.DecryptDataEncryptionKey(encryptedDEK)
	if err != nil {
		return nil, fmt.Errorf("protoutil: error decrypting data-encryption-key: %w", err)
	}

	// cache it for next time
	dec.dekCache.Put(encryptedDEK, dek)

	return dek, nil
}

// Decrypt decrypts an encrypted protobuf message.
func (dec *Decryptor) Decrypt(src *cryptpb.SealedMessage) (proto.Message, error) {
	dek, err := dec.getDataEncryptionKey(src.GetKeyId(), src.GetDataEncryptionKey())
	if err != nil {
		return nil, err
	}

	plaintext, err := dek.Decrypt(src.GetEncryptedMessage())
	if err != nil {
		return nil, err
	}

	msg, err := (&anypb.Any{TypeUrl: src.GetMessageType()}).UnmarshalNew()
	if err != nil {
		return nil, err
	}

	err = protojson.Unmarshal(plaintext, msg)
	if err != nil {
		return nil, err
	}

	return msg, nil
}
