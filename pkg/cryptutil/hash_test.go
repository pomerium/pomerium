package cryptutil

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"
)

func TestPasswordHashing(t *testing.T) {
	t.Parallel()
	bcryptTests := []struct {
		plaintext []byte
		hash      []byte
	}{
		{
			plaintext: []byte("password"),
			hash:      []byte("$2a$14$uALAQb/Lwl59oHVbuUa5m.xEFmQBc9ME/IiSgJK/VHtNJJXASCDoS"),
		},
	}

	for _, tt := range bcryptTests {
		hashed, err := HashPassword(tt.plaintext)
		if err != nil {
			t.Error(err)
		}

		if err = CheckPasswordHash(hashed, tt.plaintext); err != nil {
			t.Error(err)
		}
	}
}

// Benchmarks SHA256 on 16K of random data.
func BenchmarkSHA256(b *testing.B) {
	data, err := ioutil.ReadFile("testdata/random")
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		_ = sha256.Sum256(data)
	}
}

// Benchmarks SHA512/256 on 16K of random data.
func BenchmarkSHA512_256(b *testing.B) {
	data, err := ioutil.ReadFile("testdata/random")
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		_ = sha512.Sum512_256(data)
	}
}

func BenchmarkBcrypt(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, err := HashPassword([]byte("thisisareallybadpassword"))
		if err != nil {
			b.Error(err)
			break
		}
	}
}

func ExampleHash() {
	tag := "hashing file for lookup key"
	contents, err := ioutil.ReadFile("testdata/random")
	if err != nil {
		fmt.Printf("could not read file: %v\n", err)
		os.Exit(1)
	}
	digest := Hash(tag, contents)
	fmt.Println(hex.EncodeToString(digest))
	// Output: 9f4c795d8ae5c207f19184ccebee6a606c1fdfe509c793614066d613580f03e1
}

func TestHashProto(t *testing.T) {
	// This test will hash a protobuf message that has a map 1000 times
	// each attempt should result in the same hash if the output is
	// deterministic.
	var cur []byte
	for i := 0; i < 1000; i++ {
		s, err := structpb.NewStruct(map[string]interface{}{
			"1": "a", "2": "b", "3": "c", "4": "d",
			"5": "e", "6": "f", "7": "g", "8": "h",
		})
		assert.NoError(t, err)
		if i == 0 {
			cur = HashProto(s)
		} else {
			nxt := HashProto(s)
			if !assert.Equal(t, cur, nxt) {
				return
			}
		}
	}
}
