package cryptutil

import (
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"google.golang.org/protobuf/types/known/structpb"
)

// Benchmarks SHA256 on 16K of random data.
func BenchmarkSHA256(b *testing.B) {
	data, err := os.ReadFile("testdata/random")
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
	data, err := os.ReadFile("testdata/random")
	if err != nil {
		b.Fatal(err)
	}
	b.SetBytes(int64(len(data)))
	for i := 0; i < b.N; i++ {
		_ = sha512.Sum512_256(data)
	}
}

func ExampleHash() {
	tag := "hashing file for lookup key"
	contents, err := os.ReadFile("testdata/random")
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
		s, err := structpb.NewStruct(map[string]any{
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
