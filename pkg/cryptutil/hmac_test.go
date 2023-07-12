package cryptutil

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
	"time"
)

func TestHMAC(t *testing.T) {
	// https://groups.google.com/d/msg/sci.crypt/OolWgsgQD-8/jHciyWkaL0gJ
	hmacTests := []struct {
		key    string
		data   string
		digest string
	}{
		{
			key:    "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b",
			data:   "4869205468657265", // "Hi There"
			digest: "9f9126c3d9c3c330d760425ca8a217e31feae31bfe70196ff81642b868402eab",
		},
		{
			key:    "4a656665",                                                 // "Jefe"
			data:   "7768617420646f2079612077616e7420666f72206e6f7468696e673f", // "what do ya want for nothing?"
			digest: "6df7b24630d5ccb2ee335407081a87188c221489768fa2020513b2d593359456",
		},
	}
	for idx, tt := range hmacTests {
		keySlice, _ := hex.DecodeString(tt.key)
		dataBytes, _ := hex.DecodeString(tt.data)
		expectedDigest, _ := hex.DecodeString(tt.digest)

		keyBytes := &[32]byte{}
		copy(keyBytes[:], keySlice)

		macDigest := GenerateHMAC(dataBytes, keyBytes[:])
		if !bytes.Equal(macDigest, expectedDigest) {
			t.Errorf("test %d generated unexpected mac", idx)
		}
		if !CheckHMAC(dataBytes, macDigest, keyBytes[:]) {
			t.Errorf("test %d generated unexpected mac", idx)
		}
	}
}

func TestValidTimestamp(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		ts      string
		wantErr bool
	}{
		{"good - now", fmt.Sprint(time.Now().Unix()), false},
		{"good - now - 200ms", fmt.Sprint(time.Now().Add(-200 * time.Millisecond).Unix()), false},
		{"good - now + 200ms", fmt.Sprint(time.Now().Add(200 * time.Millisecond).Unix()), false},
		{"bad - now + 10m", fmt.Sprint(time.Now().Add(10 * time.Minute).Unix()), true},
		{"bad - now - 10m", fmt.Sprint(time.Now().Add(-10 * time.Minute).Unix()), true},
		{"malformed - non int", "pomerium", true},
		{"malformed - negative number", "-1", true},
		{"malformed - huge number", fmt.Sprintf("%d", 10*10000000000), true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidTimestamp(tt.ts); (err != nil) != tt.wantErr {
				t.Errorf("ValidTimestamp() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
