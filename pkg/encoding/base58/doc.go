// Copyright (c) 2014 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.
//
// See: https://github.com/btcsuite/btcutil/blob/master/LICENSE

/*
Package base58 provides an API for working with modified base58 and Base58Check
encodings.

# Modified Base58 Encoding

Standard base58 encoding is similar to standard base64 encoding except, as the
name implies, it uses a 58 character alphabet which results in an alphanumeric
string and allows some characters which are problematic for humans to be
excluded.  Due to this, there can be various base58 alphabets.

The modified base58 alphabet used by Bitcoin, and hence this package, omits the
0, O, I, and l characters that look the same in many fonts and are therefore
hard to humans to distinguish.
*/
package base58
