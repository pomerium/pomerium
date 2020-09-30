package shortuuid

import (
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/google/uuid"
)

type base57 struct {
	// alphabet is the character set to construct the UUID from.
	alphabet alphabet
}

// Encode encodes uuid.UUID into a string using the least significant bits
// (LSB) first according to the alphabet. if the most significant bits (MSB)
// are 0, the string might be shorter.
func (b base57) Encode(u uuid.UUID) string {
	var num big.Int
	num.SetString(strings.Replace(u.String(), "-", "", 4), 16)

	// Calculate encoded length.
	factor := math.Log(float64(25)) / math.Log(float64(b.alphabet.Length()))
	length := math.Ceil(factor * float64(len(u)))

	return b.numToString(&num, int(length))
}

// Decode decodes a string according to the alphabet into a uuid.UUID. If s is
// too short, its most significant bits (MSB) will be padded with 0 (zero).
func (b base57) Decode(u string) (uuid.UUID, error) {
	str, err := b.stringToNum(u)
	if err != nil {
		return uuid.Nil, err
	}
	return uuid.Parse(str)
}

// numToString converts a number a string using the given alpabet.
func (b *base57) numToString(number *big.Int, padToLen int) string {
	var (
		out   string
		digit *big.Int
	)

	for number.Uint64() > 0 {
		number, digit = new(big.Int).DivMod(number, big.NewInt(b.alphabet.Length()), new(big.Int))
		out += b.alphabet.chars[digit.Int64()]
	}

	if padToLen > 0 {
		remainder := math.Max(float64(padToLen-len(out)), 0)
		out = out + strings.Repeat(b.alphabet.chars[0], int(remainder))
	}

	return out
}

// stringToNum converts a string a number using the given alpabet.
func (b *base57) stringToNum(s string) (string, error) {
	n := big.NewInt(0)

	for i := len(s) - 1; i >= 0; i-- {
		n.Mul(n, big.NewInt(b.alphabet.Length()))

		index, err := b.alphabet.Index(string(s[i]))
		if err != nil {
			return "", err
		}

		n.Add(n, big.NewInt(index))
	}

	x := fmt.Sprintf("%x", n)

	if len(x) < 32 {
		// Pad the most significant bit (MSG) with 0 (zero) if the string is too short.
		x = strings.Repeat("0", 32-len(x)) + x
	} else if len(x) > 32 {
		return "", fmt.Errorf("UUID length overflow for %q", s)
	}

	return fmt.Sprintf("%s-%s-%s-%s-%s", x[0:8], x[8:12], x[12:16], x[16:20], x[20:32]), nil
}
