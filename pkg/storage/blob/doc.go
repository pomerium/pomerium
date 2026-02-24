// Package blob implements chunked reading and writing of data to blob stores
// with WORM (Write Once Read Many) integrity guarantees.
//
// WORM semantics are also enforced at the chunking protocol level because some
// providers (e.g. minio) do not natively prevent overwrites even with object
// locking enabled.
//
// This package is intended solely for use with the Pomerium recording protocol:
// https://github.com/pomerium/envoy-custom/blob/main/api/x/recording/README.md
package blob
