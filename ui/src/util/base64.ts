// The MIT License (MIT)

// Copyright (c) 2020 Blake Embrey (hello@blakeembrey.com)
// Copyright (c) 2012 Niklas von Hertzen (https://github.com/niklasvh/base64-arraybuffer)

// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:

// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.

// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

/**
 * Original source: https://github.com/niklasvh/base64-arraybuffer.
 */
const base64Chars =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const base64UrlChars =
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
const base64Lookup = new Uint8Array(256);
for (let i = 0; i < base64Chars.length; i++) {
  base64Lookup[base64Chars.charCodeAt(i)] = i;
}
// Support base64url.
base64Lookup[45 /* - */] = 62;
base64Lookup[95 /* _ */] = 63;
/**
 * Encode an `ArrayBuffer` to base64.
 */
export function encode(
  buffer: ArrayBuffer,
  chars = base64Chars,
  padding = "="
): string {
  const bytes = new Uint8Array(buffer);
  const length = bytes.length;
  let base64 = "";
  for (let i = 0; i < length; i += 3) {
    base64 += chars[bytes[i] >> 2];
    base64 += chars[((bytes[i] & 3) << 4) | (bytes[i + 1] >> 4)];
    base64 += chars[((bytes[i + 1] & 15) << 2) | (bytes[i + 2] >> 6)];
    base64 += chars[bytes[i + 2] & 63];
  }
  if (length % 3 === 2) {
    base64 = base64.slice(0, base64.length - 1) + padding;
  } else if (length % 3 === 1) {
    base64 = base64.slice(0, base64.length - 2) + padding + padding;
  }
  return base64;
}

/**
 * Encode using the base64url variant.
 */
export function encodeUrl(buffer: ArrayBuffer): string {
  return encode(buffer, base64UrlChars, "");
}

/**
 * Decode a base64 encoded string.
 */
export function decode(base64: string, lookup = base64Lookup): ArrayBuffer {
  const length = base64.length;
  let bufferLength = Math.floor(base64.length * 0.75);
  let p = 0;
  if (base64[length - 1] === "=") {
    bufferLength--;
    if (base64[length - 2] === "=") {
      bufferLength--;
    }
  }
  const bytes = new Uint8Array(bufferLength);
  for (let i = 0; i < length; i += 4) {
    const encoded1 = lookup[base64.charCodeAt(i)];
    const encoded2 = lookup[base64.charCodeAt(i + 1)];
    const encoded3 = lookup[base64.charCodeAt(i + 2)];
    const encoded4 = lookup[base64.charCodeAt(i + 3)];
    bytes[p++] = (encoded1 << 2) | (encoded2 >> 4);
    bytes[p++] = ((encoded2 & 15) << 4) | (encoded3 >> 2);
    bytes[p++] = ((encoded3 & 3) << 6) | (encoded4 & 63);
  }
  return bytes;
}
