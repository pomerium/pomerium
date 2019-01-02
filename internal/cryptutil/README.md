
## Generating random seeds
In order of preference:
- `head -c32 /dev/urandom | base64` 
- `openssl rand -base64 32 | head -c 32 | base64`
## Encrypting data

TL;DR -- Nonce reuse is a problem. AEAD isn't a clear choice right now.

[Miscreant](https://github.com/miscreant/miscreant.go)
+ AES-GCM-SIV seems to have ideal properties
+ random nonces
- ~30% slower encryption
- [not maintained by a BigCo](https://github.com/miscreant/miscreant.go/graphs/contributors)

[nacl/secretbot](https://godoc.org/golang.org/x/crypto/nacl/secretbox)
+ Fast
+ XSalsa20 wutg Poly1305 MAC provides encryption and authentication together
+ A newer standard and may not be considered acceptable in environments that require high levels of review.
-/+ maintained as an [/x/ package](https://godoc.org/golang.org/x/crypto/nacl/secretbox)
- doesn't use the underlying cipher.AEAD api. 


GCM with random nonces
+ Fastest
+ Go standard library, supported by google $
- Easy to get wrong
- IV reuse is a known weakness so keys must be rotated before birthday attack. [NIST SP 800-38D](http://csrc.nist.gov/publications/nistpubs/800-38D/SP-800-38D.pdf) recommends using the same key with random 96-bit nonces (the default nonce length) no more than 2^32 times

Further reading on tradeoffs:
- [Introducing Miscreant](https://tonyarcieri.com/introducing-miscreant-a-multi-language-misuse-resistant-encryption-library)
- [agl's post AES-GCM-SIV](https://www.imperialviolet.org/2017/05/14/aesgcmsiv.html)
- [x/crypto: add chacha20, xchacha20](https://github.com/golang/go/issues/24485s)
- [GCM cannot be used with random nonces](https://github.com/gtank/cryptopasta/issues/14s)
- [proposal: x/crypto/chacha20poly1305: add support for XChaCha20](https://github.com/golang/go/issues/23885)
- [kubernetes](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/#providers)
