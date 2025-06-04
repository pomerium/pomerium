package cryptutil

import (
	"bytes"
	"cmp"
	"crypto/x509"
	"encoding/pem"
	"iter"
	"slices"
)

// NormalizePEM takes PEM-encoded data and normalizes it.
//
// If the PEM data contains multiple certificates, signing certificates
// will be moved after the things they sign.
func NormalizePEM(data []byte) []byte {
	type Segment struct {
		ID   int
		Data []byte
	}
	var segments []Segment
	for block := range iteratePEM(data) {
		segments = append(segments, Segment{ID: len(segments), Data: block})
	}

	idToAuthorityKey := map[int]string{}
	subjectKeyToID := map[string]int{}

	for _, segment := range segments {
		block, _ := pem.Decode(segment.Data)
		if block != nil {
			if block.Type == "CERTIFICATE" {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					if len(cert.AuthorityKeyId) > 0 {
						idToAuthorityKey[segment.ID] = string(cert.AuthorityKeyId)
					}
					if len(cert.SubjectKeyId) > 0 {
						subjectKeyToID[string(cert.SubjectKeyId)] = segment.ID
					}
				}
			}
		}
	}

	depth := make([]int, len(segments))
	for i := range segments {
		id := segments[i].ID
		for {
			authorityKey, ok := idToAuthorityKey[id]
			if !ok {
				break
			}

			id, ok = subjectKeyToID[authorityKey]
			if !ok {
				break
			}
			depth[id]++
		}
	}

	slices.SortStableFunc(segments, func(x, y Segment) int {
		return cmp.Compare(depth[x.ID], depth[y.ID])
	})

	var buf bytes.Buffer
	for _, segment := range segments {
		buf.Write(segment.Data)
	}
	return buf.Bytes()
}

var (
	pemBegin = []byte("-----BEGIN ")
	pemEnd   = []byte("-----END ")
)

// splitPEM attempts to split a slice of bytes into a single pem block
// followed by the rest of the data. The pem block may contain extra
// text before the BEGIN but won't contain more than one pem block.
func splitPEM(data []byte) (before, after []byte) {
	idx1 := bytes.Index(data, pemBegin)
	if idx1 < 0 {
		return data, nil
	}

	idx2 := bytes.IndexByte(data[idx1+len(pemBegin):], '\n')
	if idx2 < 0 {
		return data, nil
	}
	idx2 += idx1 + len(pemBegin)

	idx3 := bytes.Index(data[idx2+1:], pemEnd)
	if idx3 < 0 {
		return data, nil
	}
	idx3 += idx2 + 1

	idx4 := bytes.IndexByte(data[idx3+len(pemEnd):], '\n')
	if idx4 < 0 {
		return data, nil
	}
	idx4 += idx3 + len(pemEnd)

	return data[:idx4+1], data[idx4+1:]
}

// iteratePEM iterates over all the raw PEM blocks
func iteratePEM(data []byte) iter.Seq[[]byte] {
	return func(yield func([]byte) bool) {
		rest := data
		for len(rest) > 0 {
			before, after := splitPEM(rest)
			if !yield(before) {
				return
			}
			rest = after
		}
	}
}
